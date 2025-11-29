FROM python:3.9-slim

WORKDIR /app

# Plus besoin de dépendances compliquées !
# Raw sockets est natif en Python sur Linux.

COPY monitor.py .

# Force l'affichage immédiat
ENV PYTHONUNBUFFERED=1

CMD ["python", "monitor.py"]