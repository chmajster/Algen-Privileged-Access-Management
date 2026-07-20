FROM mcr.microsoft.com/playwright/python:v1.49.1-noble

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY --chown=pwuser:pwuser backend /app/backend
COPY --chown=pwuser:pwuser frontend /app/frontend
RUN mkdir -p /app/data /tmp/algen-pam-browser-profiles && chown -R pwuser:pwuser /app/data /tmp/algen-pam-browser-profiles

WORKDIR /app/backend
USER pwuser
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
