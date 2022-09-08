# aws-lambda-http-api-node-authorizer

```bash
curl --url http://localhost:3000/hello \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb28uYmFyIiwiZXhwIjoxNjY1MjM3NjY0LCJpYXQiOjE2NjI2NDU2NjR9.fqF3eo6rPJQ7Y4qyIb4_2p_ndpOVKAyS25b1cwTjaLw'

```

```bash
curl -i "https://hnm31dsiia.execute-api.eu-west-1.amazonaws.com/hello"
# expect 403
```

With valid token

```bash
curl -i "https://hnm31dsiia.execute-api.eu-west-1.amazonaws.com/hello" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb28uYmFyIiwiZXhwIjoxNjY1MjM3NjY0LCJpYXQiOjE2NjI2NDU2NjR9.fqF3eo6rPJQ7Y4qyIb4_2p_ndpOVKAyS25b1cwTjaLw"
# expect payload
```

```bash
curl -i "https://hnm31dsiia.execute-api.eu-west-1.amazonaws.com/hello" \
    -H "Authorization: Bearer 123.456.6789"
# expect 403
```
