VERSION=${1:-latest}

docker build -t ddddn/cert-manager-webhook-huawei:"$VERSION" .
docker push ddddn/cert-manager-webhook-huawei:"$VERSION"