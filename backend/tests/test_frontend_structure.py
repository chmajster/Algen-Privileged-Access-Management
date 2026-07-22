from html.parser import HTMLParser
from pathlib import Path


class IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []
        self.html_elements = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "html":
            self.html_elements += 1
        for name, value in attrs:
            if name == "id" and value:
                self.ids.append(value)


def test_frontend_document_has_unique_ids_and_single_root():
    source = (Path(__file__).parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    parser = IdCollector()
    parser.feed(source)

    assert parser.html_elements == 1
    assert len(parser.ids) == len(set(parser.ids))
    for required_id in ("loginView", "appView", "entityModal", "content"):
        assert parser.ids.count(required_id) == 1
