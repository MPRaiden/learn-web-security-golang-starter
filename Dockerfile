FROM golang:1.27.0-alpine

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
EXPOSE 3030 4040
CMD ["go", "run", "./cmd/server"]
