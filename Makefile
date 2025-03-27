build:
	docker build . -t akamai_test

run:
	echo "Exposing container to port 8080..."
	docker run -p 8080:80 akamai_test
