# -----------------------------------------------------------------------------
# Etap 1: Budowanie - instalacja zależności systemowych i Pythona
# -----------------------------------------------------------------------------
    FROM python:3.11-slim AS builder

    # Ustawienie zmiennych środowiskowych, aby uniknąć problemów z interaktywnymi promptami podczas instalacji
    ENV DEBIAN_FRONTEND=noninteractive \
        PYTHONUNBUFFERED=1 \
        PYTHONDONTWRITEBYTECODE=1 \
        PIP_NO_CACHE_DIR=off \
        PIP_DISABLE_PIP_VERSION_CHECK=on \
        PIP_DEFAULT_TIMEOUT=100
    
    # Instalacja podstawowych narzędzi i FFmpeg oraz libpq-dev (dla psycopg2)
    # build-essential jest potrzebny dla niektórych pakietów Pythona, które kompilują kod C
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
            ffmpeg \
            libpq-dev \
            build-essential \
            # Możesz tu dodać inne pakiety systemowe, jeśli są potrzebne, np. dla Pillow:
            # libjpeg-dev zlib1g-dev libtiff-dev libfreetype6-dev libwebp-dev libopenjp2-7-dev
        && rm -rf /var/lib/apt/lists/*
    
    # Ustaw katalog roboczy
    WORKDIR /app
    
    # Skopiuj tylko plik requirements.txt, aby wykorzystać cache Dockera
    COPY requirements.txt .
    
    # Zainstaluj zależności Pythona
    RUN pip install --no-cache-dir -r requirements.txt
    
    # -----------------------------------------------------------------------------
    # Etap 2: Uruchomienie - kopiowanie aplikacji i ustawienie polecenia startowego
    # -----------------------------------------------------------------------------
    FROM python:3.11-slim AS runner
    
    # Ustawienie tych samych zmiennych środowiskowych co w builderze
    ENV DEBIAN_FRONTEND=noninteractive \
        PYTHONUNBUFFERED=1 \
        PYTHONDONTWRITEBYTECODE=1
    
    # Utwórz użytkownika nie-root dla bezpieczeństwa
    RUN addgroup --system app && adduser --system --ingroup app app
    
    # Skopiuj zainstalowane pakiety systemowe (FFmpeg, libpq5) z etapu buildera
    # To ważne, aby nie instalować ich ponownie
    COPY --from=builder /usr/bin/ffmpeg /usr/bin/ffmpeg
    # Skopiuj potrzebne biblioteki współdzielone dla FFmpeg i libpq.
    # To może wymagać iteracji, aby znaleźć wszystkie potrzebne .so pliki.
    # Poniżej kilka typowych przykładów, lista może być dłuższa.
    # Lepszym podejściem jest użycie tego samego obrazu bazowego lub instalacja w tym etapie,
    # ale dla minimalizacji rozmiaru spróbujmy skopiować.
    # Jeśli wystąpią problemy z brakującymi .so, prostszym rozwiązaniem może być
    # instalacja ffmpeg i libpq-dev również w tym etapie 'runner'.
    COPY --from=builder /lib/x86_64-linux-gnu/libpq.so.5 /lib/x86_64-linux-gnu/
    # Dodaj inne potrzebne biblioteki .so skopiowane z etapu buildera, jeśli napotkasz problemy.
    # Np. dla ffmpeg mogą być potrzebne: libavcodec.so, libavformat.so, libavutil.so, libswscale.so etc.
    # Alternatywnie, dla prostoty, można zainstalować ffmpeg i libpq-dev ponownie w tym etapie:
    # RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg libpq5 && rm -rf /var/lib/apt/lists/*
    # Dla tego poradnika, dla większej pewności działania, zainstalujemy je ponownie w etapie runner:
    RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg libpq5 && rm -rf /var/lib/apt/lists/*
    
    
    # Ustaw katalog roboczy
    WORKDIR /app
    
    # Skopiuj zainstalowane pakiety Pythona z etapu buildera
    COPY --from=builder /app/requirements.txt .
    COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
    COPY --from=builder /usr/local/bin/ /usr/local/bin/
    
    # Skopiuj kod aplikacji
    COPY . .
    
    # Zmień właściciela plików na użytkownika 'app'
    RUN chown -R app:app /app
    
    # Przełącz na użytkownika nie-root
    USER app
    
    # Ustaw zmienną środowiskową, aby Flask wiedział, gdzie jest aplikacja
    ENV FLASK_APP=app.py
    
    # Port, na którym Gunicorn będzie nasłuchiwał wewnątrz kontenera.
    # Render ustawi zmienną środowiskową $PORT i przekaże do niej ruch.
    EXPOSE 5000 # Domyślny port, jeśli $PORT nie jest ustawiony, Gunicorn może użyć 8000 lub 5000.
                # W CMD użyjemy $PORT, więc to jest bardziej informacyjne.
    
    # Polecenie uruchamiające aplikację przy użyciu Gunicorna z Eventlet dla SocketIO.
    # $PORT jest zmienną środowiskową dostarczaną przez Render.
    CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:$PORT", "app:socketio"]