# Endor Labs to GitLab Dependency Scan findings converter

**NOTE:** this is a work in progress, and has not yet been fully tested

## Usage

(Assuming a CI environment)

Requires Python 3.6 or newer

1. Place the `endorlabs-to-gitlab.py` file in your runner, using whatever method you prefer
2. Run `endorctl scan -o json [additional arguments] | python3 /path/to/endorlabs-to-gitlab.py [--warnings] [--blocks] > el-gl-dep.findings.json`
3. Add a job step to upload the findings JSON file to GitLab

Any logical equivalent (such as capturing the Endor Labs scan file and cat-piping to the python script) is acceptable.