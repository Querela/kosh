from typing import Any, Dict, List, Optional, Union

import cql
from clarin.sru.constants import (
    SRUDiagnostics,
    SRUResultCountPrecision,
    SRUVersion,
)
from clarin.sru.diagnostic import SRUDiagnostic, SRUDiagnosticList
from clarin.sru.exception import SRUException
from clarin.sru.fcs.constants import FCS_NS, FCSQueryType
from clarin.sru.fcs.server.search import (
    DataView,
    EndpointDescription,
    ResourceInfo,
    SimpleEndpointDescription,
    SimpleEndpointSearchEngineBase,
)
from clarin.sru.fcs.xml.writer import FCSRecordXMLStreamWriter
from clarin.sru.queryparser import CQLQuery, SRUQuery, SRUQueryParserRegistry
from clarin.sru.server.config import (
    DatabaseInfo,
    IndexInfo,
    LocalizedString,
    SchemaInfo,
    SRUServerConfig,
    SRUServerConfigKey,
)
from clarin.sru.server.request import SRURequest
from clarin.sru.server.result import SRUSearchResultSet
from clarin.sru.server.server import SRUServer
from clarin.sru.xml.writer import SRUXMLStreamWriter, XMLStreamWriterHelper
from flask import Flask, Response, request
from lxml import etree

from ..elastic.search import search
from ..utility.concretemethod import concretemethod
from ..utility.instance import instance
from ..utility.logger import logger
from ._api import _api

MIMETYPE_TEI_XML = "application/x-tei+xml"
X_FCS_CONTEXT_KEY = "x-fcs-context"
X_FCS_CONTEXT_SEPARATOR = ","
X_FCS_DATAVIEWS_KEY = "x-fcs-dataviews"
X_FCS_DATAVIEWS_SEPARATOR = ","


def _cql2cqp(query: CQLQuery) -> str:
    node: Union[
        cql.parser.CQLTriple, cql.parser.CQLSearchClause
    ] = query.parsed_query.root

    if isinstance(node, cql.parser.CQLTriple):
        operator = node.operator.value
        raise SRUException(
            SRUDiagnostics.UNSUPPORTED_BOOLEAN_OPERATOR,
            operator,
            message=f"Unsupported Boolean operator: {operator}",
        )

    if isinstance(node, cql.parser.CQLSearchClause):
        terms = node.term.lower().split()  # .casefold()?
        if len(terms) == 1:
            return f"{terms[0]}"

        terms = [term.strip("\"'") for term in terms]
        return " ".join(f"{term}" for term in terms)

    raise SRUException(
        SRUDiagnostics.CANNOT_PROCESS_QUERY_REASON_UNKNOWN,
        f"unknown cql node: {node}",
    )


class KoshFCSSearchResultSet(SRUSearchResultSet):
    def __init__(
        self,
        results: Optional[List[Dict[str, Any]]],
        diagnostics: SRUDiagnosticList,
        resource_pid: str,
        request: Optional[SRURequest] = None,
    ) -> None:
        super().__init__(diagnostics)
        self.request = request
        self.results = results
        self.resource_pid = resource_pid

        if request:
            self.start_record = max(1, request.get_start_record())
            self.current_record_cursor = self.start_record - 1
            self.maximum_records = (
                self.start_record - 1 + request.get_maximum_records()
            )
            self.record_count = request.get_maximum_records()
        else:
            self.start_record = 1
            self.current_record_cursor = self.start_record - 1
            self.maximum_records = 250
            self.record_count = 250

    def get_total_record_count(self) -> int:
        if self.results:
            return len(self.results)
        return -1

    def get_record_count(self) -> int:
        if self.results and len(self.results) > -1:
            if len(self.results) < self.maximum_records:
                return len(self.results)
            else:
                return self.maximum_records
        return 0

    def get_result_count_precision(
        self,
    ) -> Optional[SRUResultCountPrecision]:
        return SRUResultCountPrecision.EXACT

    def get_record_schema_identifier(self) -> str:
        if self.request:
            rsid = self.request.get_record_schema_identifier()
            if rsid:
                return rsid
        return FCS_NS  # CLARIN_FCS_RECORD_SCHEMA

    def next_record(self) -> bool:
        if self.current_record_cursor < min(
            len(self.results), self.maximum_records
        ):
            self.current_record_cursor += 1
            return True
        return False

    def get_record_identifier(self) -> str:
        return None

    def get_surrogate_diagnostic(self) -> Optional[SRUDiagnostic]:
        if (
            self.get_record_schema_identifier()
            and FCS_NS != self.get_record_schema_identifier()
        ):
            raise SRUDiagnostic(
                SRUDiagnostics.RECORD_NOT_AVAILABLE_IN_THIS_SCHEMA,
                self.get_record_schema_identifier(),
                message=f'Record is not available in record schema "{self.get_record_schema_identifier()}".',
            )
        return None

    def write_tei_dataview(self, writer: SRUXMLStreamWriter, xml: str) -> None:
        FCSRecordXMLStreamWriter.startDataView(writer, MIMETYPE_TEI_XML)

        writer = XMLStreamWriterHelper(writer)
        writer.writeXML(xml)

        FCSRecordXMLStreamWriter.endDataView(writer)

    def write_record(self, writer: SRUXMLStreamWriter) -> None:
        result = self.results[self.current_record_cursor - self.start_record]

        FCSRecordXMLStreamWriter.startResource(writer, pid=self.resource_pid)
        FCSRecordXMLStreamWriter.startResourceFragment(writer, pid=result["id"])

        marker_s = "{{{#!HLS!#}}}"
        marker_e = "{{{#!HLE!#}}}"
        doc = etree.fromstring(
            result["_highlighted"]
            .replace("<em>", marker_s)
            .replace("</em>", marker_e)
        )
        text = ", ".join(doc.xpath("//text()"))
        hits = []
        while marker_s in text and marker_e in text:
            start = text.index(marker_s)
            text = text[:start] + text[start + len(marker_s) :]
            end = text.index(marker_e)
            text = text[:end] + text[end + len(marker_e) :]
            hits.append((start, end))

        FCSRecordXMLStreamWriter.writeHitsDataView(
            writer, text=text, hits=hits, second_is_length=False
        )

        self.write_tei_dataview(writer, result["xml"])

        FCSRecordXMLStreamWriter.endResourceFragment(writer)
        FCSRecordXMLStreamWriter.endResource(writer)


class KoshFCSEndpointSearchEngine(SimpleEndpointSearchEngineBase):
    def __init__(
        self,
        endpoint_description: EndpointDescription,
        lexicon: Dict[str, Any],
        field: str = "xml",
        query_type: str = "term",
    ) -> None:
        super().__init__()
        self.endpoint_description = endpoint_description
        self.lexicon = lexicon
        self.field = field
        self.query_type = query_type

    def create_EndpointDescription(
        self,
        config: SRUServerConfig,
        query_parser_registry_builder: SRUQueryParserRegistry.Builder,
        params: Dict[str, str],
    ) -> EndpointDescription:
        return self.endpoint_description

    def do_init(
        self,
        config: SRUServerConfig,
        query_parser_registry_builder: SRUQueryParserRegistry.Builder,
        params: Dict[str, str],
    ) -> None:
        pass

    def search(
        self,
        config: SRUServerConfig,
        request: SRURequest,
        diagnostics: SRUDiagnosticList,
    ) -> SRUSearchResultSet:
        query: str
        if request.is_query_type(FCSQueryType.CQL):
            # Got a CQL query (either SRU 1.1 or higher).
            # Translate to a plain query string ...
            query_in: SRUQuery = request.get_query()
            assert isinstance(query_in, CQLQuery)
            query = _cql2cqp(query_in)
        else:
            # Got something else we don't support. Send error ...
            raise SRUException(
                SRUDiagnostics.CANNOT_PROCESS_QUERY_REASON_UNKNOWN,
                f"Queries with queryType '{request.get_query_type()}' are not supported by this CLARIN-FCS Endpoint.",
            )

        # NOTE: theoretically check for correct resource pid but since each endpoint uses its own route, it should not matter
        self._parse_params(request, diagnostics)

        try:
            results = search.entries(
                self.lexicon,
                self.field,
                query,
                self.query_type,
                request.get_maximum_records(),
                highlight=True,
            )
        except Exception as ex:
            logger().error("Error performing search: %s", ex)
            results = None
        return KoshFCSSearchResultSet(
            results, diagnostics=diagnostics, resource_pid=self.lexicon.uid
        )

    def _parse_params(
        self, request: SRURequest, diagnostics: SRUDiagnosticList
    ) -> None:
        dataviews = None
        if X_FCS_DATAVIEWS_KEY in request.get_extra_request_data_names():
            dataviews = request.get_extra_request_data(X_FCS_DATAVIEWS_KEY)
            if dataviews:
                dataviews = dataviews.split(X_FCS_DATAVIEWS_SEPARATOR)

                # for dataview in dataviews:
                #     if dataview is unknown:
                #         diagnostics.add_diagnostic(SRUDiagnostics.FCS_DIAGNOSTIC_REQUESTED_DATA_VIEW_INVALID, dataview, "An unsupported dataview was passed. Will be silently ignored.")
        logger().info("FCS request: dataviews: %s", dataviews)

        context = self.lexicon.uid
        if X_FCS_DATAVIEWS_KEY in request.get_extra_request_data_names():
            context = request.get_extra_request_data(X_FCS_CONTEXT_KEY)
            if context:
                context = context.split(X_FCS_CONTEXT_SEPARATOR)
        logger().info("FCS request: resources: %s", context)


class fcs(_api):
    """
    A CLARIN FCS 2.0 endpoint serving lexical data
    """

    @concretemethod
    def deploy(self, flask: Flask) -> None:
        """
        todo: docs
        """
        # self.field = list(self.lexicon.schema.mappings._meta._xpaths.fields.keys())[0]
        self.field = "xml"
        self.query_type = "term"
        self.server = self.build_fcs_server()
        # logger().debug("SRU/FCS server config: %s", self.server.config)
        logger().debug("Deploying FCS endpoint %s", self.path)
        flask.add_url_rule(self.path, self.path, self.handle)

    def build_fcs_server_params(self) -> Dict[str, Any]:
        return {
            SRUServerConfigKey.SRU_SUPPORTED_VERSION_MIN: SRUVersion.VERSION_1_1.version_string,
            SRUServerConfigKey.SRU_SUPPORTED_VERSION_MAX: SRUVersion.VERSION_2_0.version_string,
            SRUServerConfigKey.SRU_SUPPORTED_VERSION_DEFAULT: SRUVersion.VERSION_2_0.version_string,
            SRUServerConfigKey.SRU_TRANSPORT: "http",
            SRUServerConfigKey.SRU_HOST: instance.config["api"]["host"],
            SRUServerConfigKey.SRU_PORT: instance.config["api"]["port"],
            SRUServerConfigKey.SRU_DATABASE: self.path,
            SRUServerConfigKey.SRU_ECHO_REQUESTS: "true",
            SRUServerConfigKey.SRU_ALLOW_OVERRIDE_MAXIMUM_RECORDS: "true",
            SRUServerConfigKey.SRU_ALLOW_OVERRIDE_MAXIMUM_TERMS: "false",
            SRUServerConfigKey.SRU_ALLOW_OVERRIDE_INDENT_RESPONSE: "true",
        }

    def build_fcs_server_config(
        self, params: Dict[str, Any]
    ) -> SRUServerConfig:
        database_info = (
            DatabaseInfo(
                title=[
                    LocalizedString(
                        value=self.lexicon.title, lang="en", primary=True
                    )
                ],
                author=[
                    LocalizedString(
                        value=author,
                        lang="en",
                        primary=True if i == 0 else False,
                    )
                    for i, author in enumerate(self.lexicon.authors)
                ],
            ),
        )
        index_info = (
            IndexInfo(
                sets=[
                    IndexInfo.Set(
                        identifier="http://clarin.eu/fcs/resource",
                        name="fcs",
                        title=[
                            LocalizedString(
                                value="CLARIN Content Search",
                                lang="en",
                                primary=True,
                            )
                        ],
                    )
                ],
                indexes=[
                    IndexInfo.Index(
                        can_search=True,
                        can_scan=False,
                        can_sort=False,
                        maps=[
                            IndexInfo.Index.Map(
                                primary=True, set="fcs", name="words"
                            )
                        ],
                        title=[
                            LocalizedString(
                                value="Words", lang="en", primary=True
                            )
                        ],
                    )
                ],
            ),
        )
        schema_info = [
            SchemaInfo(
                identifier="http://clarin.eu/fcs/resource",
                name="fcs",
                location=None,
                sort=False,
                retrieve=True,
                title=[
                    LocalizedString(
                        value="CLARIN Content Search",
                        lang="en",
                        primary=True,
                    )
                ],
            )
        ]

        return SRUServerConfig.fromparams(
            params,
            database_info=database_info,
            index_info=index_info,
            schema_info=schema_info,
        )

    def build_fcs_endpointdescription(self) -> EndpointDescription:
        dataviews = [
            DataView(
                identifier="hits",
                mimetype="application/x-clarin-fcs-hits+xml",
                deliveryPolicy=DataView.DeliveryPolicy.SEND_BY_DEFAULT,
            ),
            DataView(
                identifier="tei",
                mimetype=MIMETYPE_TEI_XML,
                deliveryPolicy=DataView.DeliveryPolicy.SEND_BY_DEFAULT,
            ),
        ]
        resources = [
            ResourceInfo(
                pid=self.lexicon.uid,
                title={"en": self.lexicon.title},
                description=None,
                landing_page_uri=None,
                languages=self.lexicon.source_languages,
                available_DataViews=dataviews,
            )
        ]
        return SimpleEndpointDescription(
            version=2,
            capabilities=["http://clarin.eu/fcs/capability/basic-search"],
            supported_DataViews=dataviews,
            supported_Layers=[],
            resources=resources,
            pid_case_sensitive=False,
        )

    def build_fcs_server(self) -> SRUServer:
        params = self.build_fcs_server_params()
        config = self.build_fcs_server_config(params)
        qpr_builder = SRUQueryParserRegistry.Builder(True)
        search_engine = KoshFCSEndpointSearchEngine(
            endpoint_description=self.build_fcs_endpointdescription(),
            lexicon=self.lexicon,
            field=self.field,
            query_type=self.query_type,
        )
        search_engine.init(config, qpr_builder, params)
        return SRUServer(config, qpr_builder.build(), search_engine)

    def handle(self) -> Response:
        logger().debug("request: %s", request)
        logger().debug("request?args: %s", request.args)
        response = Response()
        self.server.handle_request(request, response)
        return response
