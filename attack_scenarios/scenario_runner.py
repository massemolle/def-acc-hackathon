"""
Calls the AI-malware tool.

Executes the result.

Catches the error/output.

Feeds it back to the tool.


Mock the "Execution": If the generated malware crashes or doesn't run, have the scenario_runner.py manually trigger a curl malicious-c2.com just to generate the network noise for BlueFlux to see
"""