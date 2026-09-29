from setuptools import setup, find_packages

setup(
    name="aciarena",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "openai>=1.75.0",
        "pydantic>=2.10.0,<3",
        "tenacity==9.0.0",
        "PyYAML==6.0.2",
        "datasets==3.6.0",
        "math-verify==0.6.0",
        "human_eval==1.0.3",
        "colorlog==6.9.0",
        "transformers==4.56.1",
        (
            "cai-framework @ "
            "https://github.com/aliasrobotics/cai/archive/"
            "6dc79257777f5f1c9500b4d2319935d34a47412e.tar.gz"
        ),
    ],
)
