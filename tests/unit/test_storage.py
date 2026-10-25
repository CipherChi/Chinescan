def test_repository_round_trip(repository) -> None:
    repository.save("finding", "one", {"title": "example", "schema_version": "1.0"})
    assert repository.get("finding", "one") == {"title": "example", "schema_version": "1.0"}


def test_repository_updates_existing_record(repository) -> None:
    repository.save("finding", "one", {"title": "old"})
    repository.save("finding", "one", {"title": "new"})
    assert repository.get("finding", "one") == {"title": "new"}
