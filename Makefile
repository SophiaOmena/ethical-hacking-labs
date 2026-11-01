.PHONY: all test test-c test-python test-java clean

all: test

test:
	./test_all.sh

test-c:
	cd c_labs && make clean && make test

test-python:
	PYTHONPATH=. python3 -m pytest python_labs/tests -v

test-java:
	cd java_labs && ./run_tests.sh

clean:
	cd c_labs && make clean
	rm -rf .pytest_cache python_labs/**/__pycache__ java_labs/target
