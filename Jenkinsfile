pipeline {
  agent any

  stages {
    stage('Checkout PR') {
      steps {
        checkout scm
        sh '''
          echo "=== Jenkins Triggered Successfully! ==="
          echo "PR Number     : ${CHANGE_ID:-None (Branch build)}"
          echo "Source Branch : ${CHANGE_BRANCH:-$BRANCH_NAME}"
          echo "Target Branch : ${CHANGE_TARGET:-N/A}"
          echo "Commit SHA    : ${GIT_COMMIT}"
        '''
      }
    }

    stage('Verify PR Diff') {
      when { changeRequest() }
      steps {
        sh '''
          echo "Running CI check on Pull Request #${CHANGE_ID}..."
          git diff --name-only origin/${CHANGE_TARGET}...HEAD
        '''
      }
    }
  }
}
