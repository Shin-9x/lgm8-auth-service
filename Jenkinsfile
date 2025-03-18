pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "tuo-user/lgm8-auth-service"
        DOCKER_TAG = "latest"
        CONTAINER_NAME = "lgm8-auth-service"
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/Shin-9x/lgm8.git'
            }
        }

        stage('Login to Docker Hub') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-hub', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh 'echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin'
                }
            }
        }

        stage('Build & Push Docker Image') {
            steps {
                script {
                    // Navigate to the microservices/lgm8-auth-service directory for the build
                    dir('microservices/lgm8-auth-service') {
                        // Build the Docker image
                        sh 'docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} -f Dockerfile .'
                        // Push the image to Docker Hub
                        sh 'docker push ${DOCKER_IMAGE}:${DOCKER_TAG}'
                    }
                }
            }
        }

        stage('Restart Service') {
            steps {
                sh 'docker stop ${CONTAINER_NAME} || true'
                sh 'docker rm ${CONTAINER_NAME} || true'
                sh 'docker pull ${DOCKER_IMAGE}:${DOCKER_TAG}'
                sh 'docker run -d --name ${CONTAINER_NAME} --network keycloak_network -p 8081:8081 ${DOCKER_IMAGE}:${DOCKER_TAG}'
            }
        }
    }
}
