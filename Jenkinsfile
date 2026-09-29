pipeline {
  agent {
    kubernetes {
      yaml '''
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: codemender-runner-sa
  containers:
  - name: codemender
    image: us-central1-docker.pkg.dev/codemender-demo-project/codemender-runner/orchestrator:latest
    imagePullPolicy: Always
    command: ["cat"]
    tty: true
    resources:
      requests:
        memory: "2Gi"
        cpu: "1000m"
      limits:
        memory: "4Gi"
        cpu: "2000m"
'''
    }
  }

  environment {
    GOOGLE_CLOUD_PROJECT       = 'codemender-demo-project'
    GCP_PROJECT_ID             = 'codemender-demo-project'
    GCP_REGION                 = 'global'
    CODEMENDER_CLI_VERSION     = 'preview'
    CODEMENDER_IS_PR_SCAN      = 'true'
    CODEMENDER_FAIL_ON_FINDINGS = 'true'
    CODEMENDER_SKIP_VERIFY     = 'true'
    CODEMENDER_SANDBOX_ENABLED = 'false'
    CODEMENDER_STORAGE_MODE    = 'local'
    CODEMENDER_GCS_BUCKET      = 'codemender-local-transit'
    GITHUB_REPO_URL            = 'https://github.com/sanvisasanapuri/codemender-jenkins-demo.git'
    PY                         = '/opt/codemender/venv/bin/python3'
    ORCH                       = '/opt/codemender/orchestrator.py'
  }

  stages {
    stage('1. Scan & Dispatch') {
      when { changeRequest() }
      steps {
        container('codemender') {
          withCredentials([usernamePassword(
            credentialsId: 'github-pat-cred',
            usernameVariable: 'GH_USER',
            passwordVariable: 'GITHUB_PAT'
          )]) {
            sh '''
              set -e
              git config --global --add safe.directory "*"
              export GITHUB_TOKEN="${GITHUB_PAT}"
              export CODEMENDER_SCAN_ID="jenkins-${BUILD_NUMBER}"
              export WORKSPACE_DIR="/tmp/cm_work"
              mkdir -p "${WORKSPACE_DIR}"

              git fetch origin "${CHANGE_BRANCH}" "${CHANGE_TARGET:-main}" 2>/dev/null || true
              export CODEMENDER_TARGET_SHA=$(git rev-parse "origin/${CHANGE_BRANCH}" 2>/dev/null || git rev-parse HEAD)
              export CODEMENDER_RUN_MODE="scan"

              ${PY} ${ORCH}
            '''
          }
        }
      }
    }

    stage('2. Parallel Fix') {
      when { changeRequest() }
      steps {
        container('codemender') {
          withCredentials([usernamePassword(
            credentialsId: 'github-pat-cred',
            usernameVariable: 'GH_USER',
            passwordVariable: 'GITHUB_PAT'
          )]) {
            sh '''
              set -e
              git config --global --add safe.directory "*"
              export GITHUB_TOKEN="${GITHUB_PAT}"
              export CODEMENDER_SCAN_ID="jenkins-${BUILD_NUMBER}"
              export WORKSPACE_DIR="/tmp/cm_work"

              git fetch origin "${CHANGE_BRANCH}" "${CHANGE_TARGET:-main}" 2>/dev/null || true
              export CODEMENDER_TARGET_SHA=$(git rev-parse "origin/${CHANGE_BRANCH}" 2>/dev/null || git rev-parse HEAD)

              M="/tmp/codemender_local_storage/${CODEMENDER_GCS_BUCKET}/scans/${CODEMENDER_SCAN_ID}/manifest.json"
              FC=$(jq -r '.findings_count // 0' "${M}")
              echo "Discovered active PR findings: ${FC}"

              if [ "${FC}" -gt 0 ]; then
                N=$(jq -r '.partition_urls | length' "${M}")
                echo "Running ${N} worker partition(s)..."

                export CODEMENDER_TOTAL_WORKERS="${N}"
                export CODEMENDER_BASE_WORKSPACE_URL=$(jq -r '.base_workspace_url' "${M}")
                export CODEMENDER_PARTITION_URLS=$(jq -c '.partition_urls' "${M}")
                export CODEMENDER_UPLOAD_URLS=$(jq -c '.upload_urls' "${M}")
                export CODEMENDER_METADATA_URLS=$(jq -c '.metadata_urls' "${M}")

                for i in $(seq 0 $((N - 1))); do
                  export CODEMENDER_RUN_MODE="worker"
                  export CODEMENDER_WORKER_INDEX="${i}"
                  ${PY} ${ORCH}
                done
              fi
            '''
          }
        }
      }
    }

    stage('3. Aggregate & Gate') {
      when { changeRequest() }
      steps {
        container('codemender') {
          withCredentials([usernamePassword(
            credentialsId: 'github-pat-cred',
            usernameVariable: 'GH_USER',
            passwordVariable: 'GITHUB_PAT'
          )]) {
            sh '''
              set -e
              git config --global --add safe.directory "*"
              export GITHUB_TOKEN="${GITHUB_PAT}"
              export CODEMENDER_SCAN_ID="jenkins-${BUILD_NUMBER}"
              export WORKSPACE_DIR="/tmp/cm_work"

              git fetch origin "${CHANGE_BRANCH}" "${CHANGE_TARGET:-main}" 2>/dev/null || true
              export CODEMENDER_TARGET_SHA=$(git rev-parse "origin/${CHANGE_BRANCH}" 2>/dev/null || git rev-parse HEAD)
              export CODEMENDER_RUN_MODE="aggregate"

              ${PY} ${ORCH}
              cp -f /tmp/cm_work/report.* . 2>/dev/null || true
            '''
          }
        }
        archiveArtifacts artifacts: 'report.*', allowEmptyArchive: true
      }
    }
  }
}
