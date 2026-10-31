import yaml


def load_settings(text: str) -> dict:
    # Reachable: parses untrusted-looking input with the full loader.
    return yaml.load(text, Loader=yaml.FullLoader)


if __name__ == "__main__":
    print(load_settings("name: hedwig"))
