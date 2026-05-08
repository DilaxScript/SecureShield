from pathlib import Path

from setuptools import find_packages, setup


BASE_DIR = Path(__file__).parent
README = (BASE_DIR / "README.md").read_text(encoding="utf-8") if (BASE_DIR / "README.md").exists() else "SecureShield container security platform."


setup(
    name="secureshield",
    version="0.1.0",
    description="Container security scanner with CLI and web API.",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Vishnu",
    packages=find_packages(exclude=("frontend", "backend", "venv")),
    include_package_data=True,
    package_data={
        "secureshield": [
            "assets/logo.png",
            "web/static/*",
            "web/static/assets/*",
        ]
    },
    install_requires=[
        "click>=8.1.0",
        "fastapi>=0.110.0",
        "psycopg>=3.3.0",
        "sqlalchemy>=2.0.0",
        "uvicorn>=0.29.0",
    ],
    entry_points={
        "console_scripts": [
            "secureshield=secureshield.cli:main",
        ]
    },
    python_requires=">=3.11",
)
