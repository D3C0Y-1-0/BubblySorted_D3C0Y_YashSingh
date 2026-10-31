import yaml


def load_settings(text: str) -> dict:
    # Not reachable: safe_load never constructs arbitrary objects.
    return yaml.safe_load(text)


if __name__ == "__main__":
    print(load_settings("name: hedwig"))
