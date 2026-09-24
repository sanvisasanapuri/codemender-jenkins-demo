pipeline {
  agent {
    kubernetes {
      defaultContainer 'codemender'
      yaml '''
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: codemender-runner-sa
  containers:
  - name: codemender
    image: us-central1-docker.pkg.dev/codemender-demo-project/codemender-runner/orchestrator:latest
    command: ["sleep"]
    args: ["9999999"]
    tty: true
    resources:
      requests:
        cpu: "200m"
        memory: "512Mi"
'''
    }
  }
  environment {
    CODEMENDER_IS_PR_SCAN       = 'true'
    CODEMENDER_FAIL_ON_FINDINGS = 'true'
    CODEMENDER_STORAGE_MODE     = 'local'
    CODEMENDER_GCS_BUCKET       = 'codemender-local-transit'
    GCS_BUCKET_NAME             = 'codemender-local-transit'
  }
  stages {
    stage('Checkout PR') {
      steps { checkout scm }
    }
    stage('Run CodeMender PR Security Gate') {
      when { changeRequest() }
      steps {
        withCredentials([usernamePassword(
          credentialsId: 'github-pat-cred',
          usernameVariable: 'GH_USER',
          passwordVariable: 'GITHUB_TOKEN'
        )]) {
          sh '''
            [ -f /usr/local/bin/cm.real ] || cp /usr/local/bin/cm /usr/local/bin/cm.real
            cp cm_fallback.py /usr/local/bin/cm && chmod +x /usr/local/bin/cm
            export REPO_OWNER_AND_NAME="sanvisasanapuri/codemender-jenkins-demo"
            export PR_NUMBER="${CHANGE_ID}"
            export COMMIT_SHA="$(git rev-parse HEAD)"
            export BASE_REF="origin/${CHANGE_TARGET:-main}"
            git fetch origin "${CHANGE_TARGET:-main}" --depth=20 || true
            /opt/codemender/venv/bin/python3 /opt/codemender/src/scan.py
            for FID in $(jq -r '.[]' /tmp/finding_ids.json 2>/dev/null); do
              /opt/codemender/venv/bin/python3 /opt/codemender/src/worker.py "${FID}"
            done
            /opt/codemender/venv/bin/python3 /opt/codemender/src/aggregate.py
          '''
        }
      }
    }
  }
}
