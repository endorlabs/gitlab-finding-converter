#!/usr/bin/env python3
import json as jsonlib
import sys, os, re, argparse

# try:
#     from rich import print
# except ModuleNotFoundError as e:
#     print("Warning: " + str(e), file=sys.stderr)

def grouse(*msg, sep=' ', end="\n", file=sys.stderr, **kwargs):
    print(*msg, sep=sep, end=end, file=file, **kwargs)

class DotDict(dict):
    _reBrackets = re.compile('^\\[(\\d+)\\]$')
    def getdot(self, path, default=None):
        ptr = self
        for item in path.split('.'):
            res = self._reBrackets.match(item)
            if res:
                item = int(res.group(1))
                ptr = ptr[item]
            else:
                ptr = ptr.get(item, None)

            if ptr is None:
                return default
        return ptr


# ingest findings from stdin
def read_json_stream(fh=sys.stdin):
    findings_str = ''
    start_json = False
    for line in fh.readlines():
        if not start_json:
            if line.strip().startswith('{'):
                start_json=True
            else:
                continue

        # add to the json stream
        findings_str += line

    return jsonlib.loads(findings_str)


def parse_findings_for_context(findings, context='all_findings'):
    # process a context
    gitlab_context = context  # TODO make this an argument
    gitlab_findings = []
    gitlab_remediations = []
    grouse(f"Converting {len(findings[gitlab_context])} findings in the {gitlab_context} context to GitLab format")
    for raw_finding in findings[gitlab_context]:
        finding = DotDict(raw_finding)
        # grouse(finding.getdot('meta.description'))
    
        severity = finding.getdot('spec.finding_metadata.vulnerability.spec.cvss_v3_severity.level', 'Unknown').replace('LEVEL_', '', 1)
        entry = {
            'id': finding.getdot('uuid'),
            'category': 'dependency_scanning',
            'name': finding.getdot('meta.description', 'No Description Found'),
            'description': finding.getdot('spec.summary', 'No summary available') ,
            'severity': severity.title(),
            'solution': finding.getdot('spec.remediation', 'No remediation path is known'),
            'scanner': {'id': 'endorlabs', 'name': 'Endor Labs dependency scan'},
            'location': {
            'file': finding.getdot('spec.dependency_file_paths.[0]', '__unknown_file__'),
            "dependency": {
                "package": {
                "name": finding.getdot('spec.target_dependency_name', '__unknown__'),
                },
                "version": finding.getdot('spec.target_dependency_version', '__unknown__')
            }
            },
            'identifiers': [
            {
                'type': 'endorlabs',
                'name': f"EndorLabs-{finding.getdot('uuid', '__unknown__')}",
                'value': finding.getdot('uuid', '__unknown__'),
                'url': f"https://app.endorlabs.com/t/{finding.getdot('tenant_meta.namespace')}"\
                    +f"/findings/{finding.get('uuid','0')}"  #TODO better link to finding
            },
            ],
            'links': [ { 'url': ref['url'] } for ref in finding.getdot('spec.finding_metadata.vulnerability.spec.references', []) ],  # if ref['type'] in ['REFERENCE_TYPE_ADVISORY']
        }
        xtra_id = None
        if finding.getdot('spec.extra_key', None) is not None:
            xkey = finding.getdot('spec.extra_key')
            if xkey.startswith('GHSA-'):
                xtra_id = {
                    'type': 'ghsa',
                    'name': xkey,
                    'value': xkey,
                    'url': f"https://github.com/advisories/{xkey}"
                }
            elif xkey.startswith('CVE-'):
                xtra_id = {
                    'type': 'nvd',
                    'name': xkey,
                    'value': xkey,
                    'url': f"https://nvd.nist.gov/vuln/detail/{xkey}"
                }
            elif xkey.find('://') > -1:
                if xkey.startswith('https://'):
                    xtra_id = {
                        'type': 'web',
                        'name': xkey,
                        'value': xkey,
                        'url': xkey
                    }
                else:
                    pass  # It's a url that's not an HTTPS URL, so treat it as nothing
            else:
                grouse(f"Reference '{xkey}' doesn't have a known URL pattern")
        if xtra_id is not None:
            entry['identifiers'].append(xtra_id)
        # grouse(entry)
        gitlab_findings.append(entry)
        # TODO append remediations?
        # grouse(f"Processed {len(gitlab_findings)} entries")
    
    return gitlab_findings

def gitlab_doc(parsed_findings):
    return { 'version': '2.0', 'vulnerabilites': parsed_findings }
    # TODO add remedaitions?

if __name__ == '__main__':

    contexts = []
    argparser = argparse.ArgumentParser(
        description='Converts Endor Labs findings in JSON format (on STDIN) to GitLab Dependency Scaning findings format (on STDOUT)',
        epilog='options can be combined; default behavior is to report all findings')
    argparser.add_argument('--warnings', action='store_true', help='Report policy warnings')
    argparser.add_argument('--blocks', action='store_true', help='Report policy violations')
    # argparser.add_argument('--help')
    args = argparser.parse_args()
    args.warnings and contexts.append('warning_findings')
    args.blocks and contexts.append('blocking_findings')
    if len(contexts) == 0:
        contexts = [ 'all_findings' ]

    findings = read_json_stream(sys.stdin)
    contexts_in_stream = [key for key in findings.keys() if key.endswith('_findings')]
    findings_count = len(findings.get('all_findings', []))
    grouse(f"Found {findings_count} findings in {len(contexts_in_stream)} contexts")
    if findings_count == 0:
        grouse("Without findings, I have nothing to do")
        exit(0)

    output_findings = []

    for context in contexts:
        output_findings.extend(parse_findings_for_context(findings, context))

    jsonlib.dump(
        gitlab_doc(output_findings),
        sys.stdout,
        indent=3)


