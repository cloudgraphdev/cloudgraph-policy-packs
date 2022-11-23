export default {
  id: 'gcp-cis-1.3.0-4.10',
  title:
    'GCP CIS 4.10 In order to maintain the highest level of security all connections to an application should be secure by default.',
  description: `In order to maintain the highest level of security all connections to an application should be
  secure by default.`,
  rationale:
    'Insecure HTTP connections maybe subject to eavesdropping which can expose sensitive data.',
  audit: `Verify that the app.yaml file controlling the application contains a line which enforces
  secure connections. For example

          handlers:
          - url: /.*
            secure: always
            redirect_http_response_code: 301
            script: auto

  https://cloud.google.com/appengine/docs/standard/python3/config/appref`,
  remediation: `Add a line to the app.yaml file controlling the application which enforces secure
  connections. For example

          handlers:
          - url: /.*
            secure: always
            redirect_http_response_code: 301
            script: auto

  https://cloud.google.com/appengine/docs/standard/python3/config/appref`,
  references: [
    'https://cloud.google.com/appengine/docs/standard/python3/config/appref',
    'https://cloud.google.com/appengine/docs/flexible/nodejs/configuring-your-app-with-app-yaml',
  ],
  severity: 'medium',
}
