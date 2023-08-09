# Endor Labs to GitLab Dependency Scan findings converter

**NOTE:** this is a work in progress, and has not yet been fully tested

## Usage

(Assuming a CI environment)

Requires Python 3.6 or newer

1. Place the `endorlabs-to-gitlab.py` file in your runner, using whatever method you prefer
2. Run `endorctl scan -o json [additional arguments] | python3 /path/to/endorlabs-to-gitlab.py [--warnings] [--blocks] > el-gl-dep.findings.json`
3. Add a job step to upload the findings JSON file to GitLab

Any logical equivalent (such as capturing the Endor Labs scan file and cat-piping to the python script) is acceptable.

## NOTES

- This script is not currently aware of the `endorctl` version in use, so it will report the scanner version as '0.0.0.'

- This script is not currently aware of the scan start time and end time; it will "lie" by putting the current time of the script run in both fields

- This script is not currently aware of the success or failure state of the scan; it will "lie" and say the scan is successful

The above items are the result of this script being a "temporary patch" while Endor Labs builds official support for the Dependency Scan report format defined by GitLab
