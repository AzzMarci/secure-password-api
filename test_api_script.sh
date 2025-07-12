#!/bin/bash

# Script di test per l'API del Generatore di Password Sicure
# Assicurati che l'API sia in esecuzione su localhost:8001

BASE_URL="http://localhost:8001"
VERBOSE=false

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funzione per stampare messaggi colorati
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Funzione per verificare se l'API è online
check_api_status() {
    print_status "Verifica stato API..."
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health")
    
    if [ "$response" = "200" ]; then
        print_success "API online e funzionante"
        return 0
    else
        print_error "API non raggiungibile (HTTP $response)"
        return 1
    fi
}

# Funzione per eseguire test con output formattato
run_test() {
    local test_name="$1"
    local endpoint="$2"
    local data="$3"
    
    print_status "Test: $test_name"
    
    if [ -z "$data" ]; then
        # GET request
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
    else
        # POST request
        response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi
    
    # Separa body e status code
    body=$(echo "$response" | sed '$d')
    status_code=$(echo "$response" | tail -n1)
    
    if [ "$status_code" = "200" ]; then
        print_success "Test completato con successo"
        if [ "$VERBOSE" = "true" ]; then
            echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
        else
            # Mostra solo alcuni campi chiave
            echo "$body" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'password' in data:
        print('Password:', data['password'][:20] + '...' if len(data['password']) > 20 else data['password'])
        print('Lunghezza:', data.get('length', 'N/A'))
        print('Forza:', data.get('strength', 'N/A'))
        print('Entropia:', data.get('entropy_bits', 'N/A'), 'bit')
    elif 'passwords' in data:
        print('Passwords generate:', len(data['passwords']))
        print('Prima password:', data['passwords'][0]['password'][:20] + '...' if len(data['passwords'][0]['password']) > 20 else data['passwords'][0]['password'])
    else:
        print(json.dumps(data, indent=2))
except:
    print(sys.stdin.read())
" 2>/dev/null || echo "$body"
        fi
    else
        print_error "Test fallito (HTTP $status_code)"
        echo "$body"
    fi
    
    echo ""
}

# Funzione per mostrare l'help
show_help() {
    echo "Usage: $0 [OPTIONS] [TESTS]"
    echo ""
    echo "OPTIONS:"
    echo "  -v, --verbose    Output dettagliato dei test"
    echo "  -h, --help       Mostra questo help"
    echo ""
    echo "TESTS:"
    echo "  all              Esegue tutti i test (default)"
    echo "  basic            Test di base (generazione password semplice)"
    echo "  bulk             Test generazione multipla"
    echo "  readable         Test password leggibili"
    echo "  pronounceable    Test password pronunciabili"
    echo "  passphrase       Test passphrase"
    echo "  compromised      Test controllo password compromesse"
    echo "  health           Test endpoint di health"
    echo ""
    echo "Esempi:"
    echo "  $0                    # Esegue tutti i test"
    echo "  $0 -v basic          # Test di base con output dettagliato"
    echo "  $0 readable passphrase  # Solo test per password leggibili e passphrase"
}

# Test specifici
test_health() {
    run_test "Health Check" "/api/health"
}

test_basic() {
    run_test "Generazione Password Base" "/api/generate" '{
        "length": 16,
        "include_uppercase": true,
        "include_lowercase": true,
        "include_numbers": true,
        "include_symbols": true,
        "exclude_ambiguous": true,
        "security_standard": "NIST"
    }'
}

test_bulk() {
    run_test "Generazione Password Multiple" "/api/generate/bulk" '{
        "count": 3,
        "length": 12,
        "include_uppercase": true,
        "include_lowercase": true,
        "include_numbers": true,
        "include_symbols": false,
        "exclude_ambiguous": true,
        "security_standard": "OWASP"
    }'
}

test_readable() {
    run_test "Password Leggibile" "/api/generate/readable" '{
        "word_count": 4,
        "separator": "-",
        "include_numbers": true,
        "capitalize": true
    }'
}

test_pronounceable() {
    run_test "Password Pronunciabile" "/api/generate/pronounceable" '{
        "length": 14,
        "include_uppercase": true,
        "include_lowercase": true,
        "include_numbers": true,
        "include_symbols": true,
        "exclude_ambiguous": true,
        "security_standard": "NIST"
    }'
}

test_passphrase() {
    run_test "Passphrase" "/api/generate/passphrase" '{
        "length": 32,
        "include_spaces": true
    }'
}

test_compromised() {
    print_warning "Test controllo password compromesse (usando una password comune)"
    run_test "Controllo Password Compromessa" "/api/check-compromised" '{
        "password": "password123"
    }'
}

# Parsing degli argomenti
TESTS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        all|basic|bulk|readable|pronounceable|passphrase|compromised|health)
            TESTS+=("$1")
            shift
            ;;
        *)
            print_error "Argomento sconosciuto: $1"
            show_help
            exit 1
            ;;
    esac
done

# Se non sono specificati test, esegui tutti
if [ ${#TESTS[@]} -eq 0 ]; then
    TESTS=("all")
fi

# Banner
echo "========================================"
echo "  Test API Generatore Password Sicure"
echo "========================================"
echo ""

# Verifica che l'API sia online
if ! check_api_status; then
    print_error "Impossibile continuare senza API attiva"
    echo ""
    echo "Per avviare l'API:"
    echo "  python3 main.py"
    echo "  # oppure"
    echo "  uvicorn main:app --host 0.0.0.0 --port 8001"
    exit 1
fi

echo ""

# Esegui i test richiesti
for test in "${TESTS[@]}"; do
    case $test in
        all)
            test_health
            test_basic
            test_bulk
            test_readable
            test_pronounceable
            test_passphrase
            test_compromised
            ;;
        health)
            test_health
            ;;
        basic)
            test_basic
            ;;
        bulk)
            test_bulk
            ;;
        readable)
            test_readable
            ;;
        pronounceable)
            test_pronounceable
            ;;
        passphrase)
            test_passphrase
            ;;
        compromised)
            test_compromised
            ;;
    esac
done

echo "========================================"
echo "  Test completati!"
echo "========================================"