# The base image must be pinned to an immutable digest before release builds.
# Python 3.12 image digest is intentionally not guessed; registry access is
# outside the package-index-only network scope of this environment.
FROM python:3.12-slim-bookworm AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY chinescan ./chinescan
RUN python -m pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system chinescan && useradd --system --gid chinescan --create-home chinescan
WORKDIR /app
COPY --from=build /build/dist/*.whl /tmp/chinescan.whl
RUN python -m pip install --no-cache-dir /tmp/chinescan.whl && rm /tmp/chinescan.whl
USER chinescan
ENTRYPOINT ["chinescan"]
CMD ["--help"]
