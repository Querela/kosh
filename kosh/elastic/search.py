from datetime import datetime
from re import split
from typing import Any, Dict, List

from elasticsearch_dsl import Search

from .entry import entry


class search:
    """
    todo: docs
    """

    @classmethod
    def ids(
        cls,
        lexicon: Dict[str, Any],
        ids: List[str],
    ) -> List[Dict[str, str]]:
        """
        todo: docs
        """
        find = entry(lexicon).schema()

        try:
            return [
                {**item.to_dict(), "id": item.meta.id}
                for item in find.mget(ids)
                if item
            ]
        except Exception:
            return []

    @classmethod
    def entries(
        cls,
        lexicon: Dict[str, Any],
        field: str,
        query: str,
        query_type: str,
        size: int,
        offset: int = 0,
        highlight: bool = False,
    ) -> List[Dict[str, str]]:
        """
        todo: docs
        """
        find = Search(index=lexicon.pool).query(
            query_type, **{field if field != "id" else "_id": query}
        )
        if highlight and field != "id":
            find = find.highlight(field, fragment_size=100000)

        try:
            results = find[offset:size].execute()

            if highlight and field != "id":
                return [
                    {
                        **item["_source"].to_dict(),
                        "id": item["_id"],
                        "created": datetime(
                            *map(int, split(r"\D", item["_source"]["created"]))
                        ),
                        "_highlighted": (
                            list(item["highlight"][field]) + [None]
                        )[0],
                    }
                    for item in results.hits.hits
                ]

            return [
                {
                    **item.to_dict(),
                    "id": item.meta.id,
                    "created": datetime(*map(int, split(r"\D", item.created))),
                }
                for item in results
            ]
        except Exception:
            return []
