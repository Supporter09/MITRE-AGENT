#!/usr/bin/env python3
import sys
import json
import yaml  # Requires PyYAML. Install it via: pip install pyyaml

def convert_yaml_to_json(yaml_file, json_file):
    try:
        with open(yaml_file, "r") as f:
            # Load YAML data using safe_load to avoid potential security issues
            data = yaml.safe_load(f)
    except Exception as e:
        sys.exit(f"Error reading YAML file {yaml_file}: {e}")

    try:
        with open(json_file, "w") as f:
            # Convert Python object to JSON with indentation for readability
            json.dump(data, f, indent=2)
    except Exception as e:
        sys.exit(f"Error writing JSON file {json_file}: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: {} input.yaml output.json".format(sys.argv[0]))
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    convert_yaml_to_json(input_file, output_file)
    print(f"Successfully converted '{input_file}' to '{output_file}'.")

if __name__ == '__main__':
    main()
