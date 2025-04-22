# Flask API

This project is a simple Flask application that includes a health check API.

## Setup Instructions

1. Clone the repository:
   ```
   git clone <repository-url>
   cd flask-api
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python src/app.py
   ```

## Usage

The health check API can be accessed at the following endpoint:
```
GET /health
```
This endpoint returns a JSON response indicating the server's health status.