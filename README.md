# sign4-request-signing-lambda-function

This function signs POST/GET request before sending it to the APIGW invocation endpoint

# Package the python 3.8 lambda function

- pip install --target ./package requests

- cd package

- zip -r ../function.zip .

- cd..

- zip -g function.zip index.py
