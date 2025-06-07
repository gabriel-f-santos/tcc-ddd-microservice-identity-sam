# Comando único que sempre funciona
rm -rf .aws-sam/ && \
sam build && \
sam deploy --force-upload --no-confirm-changeset
