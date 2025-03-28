include vars.env

build:
	docker buildx build --secret id=PUBLIC_KEY_FILE,src=publicKey.pem \
	--secret id=PRIVATE_KEY_FILE,src=privateKey.pem \
	--secret id=VAULT_KEY_FILE,src=vaultKey.txt \
	. -t akamai_test 

run:
	docker run -p 8080:80 --env-file vars.env akamai_test

test:
	docker run -p 8080:80 --env-file vars.env akamai_test pytest