set -e

echo "Generating Python proto files..."

cd proto || exit
./generate_python_proto.sh

cd ../py
# If no virtualenv exists, create one
if [ ! -d ".venv" ]; then
    echo "No virtualenv found. Creating one..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "Installing Python dependencies..."
sleep 1
pip install -r requirements.txt