# Pin both stages to the verified multi-platform manifest digest.
FROM python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS build
WORKDIR /build
COPY pyproject.toml uv.lock README.md ./
COPY chinescan ./chinescan
RUN python -m pip install --no-cache-dir uv==0.13.5 build==1.6.1 \
    && uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file /build/requirements.txt \
    && python -m build --wheel

FROM python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system chinescan && useradd --system --gid chinescan --create-home chinescan
WORKDIR /app
COPY --from=build /build/dist/*.whl /tmp/
COPY --from=build /build/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && python -m pip install --no-cache-dir --no-deps /tmp/*.whl \
    && rm /tmp/*.whl /tmp/requirements.txt
USER chinescan
ENTRYPOINT ["chinescan"]
CMD ["--help"]
