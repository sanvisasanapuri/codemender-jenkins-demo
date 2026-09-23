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
    command:
    - sleep
    args:
    - "9999999"
    tty: true
    resources:
      requests:
        cpu: "200m"
        memory: "512Mi"
'''
    }
  }

  environment {
    CODEMENDER_RUN_MODE         = 'sequential'
    CODEMENDER_IS_PR_SCAN       = 'true'
    CODEMENDER_FAIL_ON_FINDINGS = 'true'
    CODEMENDER_STORAGE_MODE     = 'local'
  }

  stages {
    stage('Checkout PR') {
      steps {
        checkout scm
      }
    }

    stage('Run CodeMender Orchestrator (Artifact Registry Image)') {
      when { changeRequest() }
      steps {
        withCredentials([usernamePassword(
          credentialsId: 'github-pat-cred',
          usernameVariable: 'GITHUB_USER',
          passwordVariable: 'GITHUB_TOKEN'
        )]) {
          sh '''
            echo "=== Running CodeMender from Artifact Registry Container ==="
            /usr/local/bin/cm --version
            /opt/codemender/venv/bin/python3 /opt/codemender/orchestrator.py \
              --pr-number "${CHANGE_ID}" \
              --branch "${CHANGE_BRANCH}" \
              --base-branch "${CHANGE_TARGET}" \
              --repo "sanvisasanapuri/codemender-jenkins-demo"
          '''
        }
      }
    }
  }
}
