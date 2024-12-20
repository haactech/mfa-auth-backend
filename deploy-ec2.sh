#!/bin/bash

# Configuración de variables
EC2_IP="10.0.1.39"
BASTION_IP="3.89.195.1"
KEY_PATH="~/Downloads/creze-test-haac.pem"
ECR_REPO_NAME="creze-mfa-backend"
APP_VERSION="1.0.0"
AWS_REGION="us-east-1"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Iniciando despliegue en EC2...${NC}"

# 1. Copiar scripts y configuraciones a través del bastión
echo -e "\n${YELLOW}Copiando archivos de configuración...${NC}"
scp -i ${KEY_PATH} -o ProxyCommand="ssh -i ${KEY_PATH} -W %h:%p ec2-user@${BASTION_IP}" \
    docker-compose.yml ec2-user@${EC2_IP}:~/

if [ $? -ne 0 ]; then
    echo -e "${RED}Error al copiar archivos${NC}"
    exit 1
fi

# 2. Conectar al EC2 y ejecutar los comandos de despliegue
echo -e "\n${YELLOW}Conectando a EC2 y desplegando aplicación...${NC}"
ssh -i ${KEY_PATH} -o ProxyCommand="ssh -i ${KEY_PATH} -W %h:%p ec2-user@${BASTION_IP}" \
    ec2-user@${EC2_IP} << 'EOF'

# Autenticar con ECR
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin \
    ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Detener y remover contenedores existentes
docker-compose down

# Eliminar imágenes antiguas
docker rmi $(docker images -q ${ECR_REPO_NAME}) 2>/dev/null || true

# Descargar nueva imagen
docker pull ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${APP_VERSION}

# Levantar nuevos contenedores
docker-compose up -d

EOF

if [ $? -ne 0 ]; then
    echo -e "${RED}Error durante el despliegue en EC2${NC}"
    exit 1
fi

echo -e "\n${GREEN}¡Despliegue completado exitosamente!${NC}"