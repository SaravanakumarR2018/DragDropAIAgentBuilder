#!/bin/bash

# Simple script for local Docker testing with Postgres
# Usage: ./local-docker-test.sh [build|run|stop]

set -e

# Change to git root directory
echo "📂 Changing to git root directory..."
GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$GIT_ROOT" ]; then
    echo "❌ Error: Not in a git repository!"
    echo "This script must be run from within a git repository."
    exit 1
fi

cd "$GIT_ROOT"
echo "✅ Now in: $(pwd)"
echo ""

# Function to display simple help
show_help() {
    cat << 'EOF'
🐳 Local Docker Testing Script

📋 Usage:
    ./local-docker-test.sh [COMMAND] [OPTIONS]

🔧 Commands:
    build              Build Docker image (prompts for custom tag or uses timestamp)
    run [IMAGE_TAG]    Run Docker containers (prompts for port, default: 7860)
    stop              Stop Docker containers (interactive menu)
    -h, --help        Show this help message
    -v, --verbose     Show detailed help with examples

💡 Quick Start:
    export VITE_CLERK_PUBLISHABLE_KEY="pk_test_xxxxxxxxxxxx"
    ./local-docker-test.sh build
    ./local-docker-test.sh run
    ./local-docker-test.sh stop

📚 For detailed examples and options, run:
    ./local-docker-test.sh --verbose

EOF
}

# Function to display verbose help
show_verbose_help() {
    cat << 'EOF'
🐳 Local Docker Testing Script - Detailed Help

📋 Usage:
    ./local-docker-test.sh [COMMAND] [OPTIONS]

🔧 Commands:
    build              Build the Docker image with staging environment variables
    run [IMAGE_TAG]    Run Docker containers (Langflow + Postgres)
                      - If IMAGE_TAG is provided, uses that specific image
                      - If omitted, shows interactive menu to select from available images
    stop              Stop and remove Docker containers
    -h, --help        Show this help message
    -v, --verbose     Show this detailed help

📖 Description:
    This script helps you test the Langflow Docker container locally with Postgres.
    
    🔨 Build: Creates the Docker image using staging environment variables
              matching the GitHub workflow configuration.
              - Prompts for custom tag (e.g., branch name) or uses timestamp
              - Allows you to organize builds by feature/branch
    
    ▶️  Run:   Starts two containers:
              - Postgres database (custom port based on Langflow port)
              - Langflow application (custom port, default: 7860)
              - Prompts for port selection to allow multiple instances
              - Uses unique container names to avoid conflicts
              Interactive menu allows you to select from available images.
              Uses .env-file for runtime configuration.
    
    🛑 Stop:  Lists all running Langflow containers and provides options:
              - Stop ALL containers
              - Stop default containers only
              - Stop specific container by port
              Interactive menu for safe container management.

⚙️  Prerequisites:
    1. Docker must be installed and running
    2. .env-file must exist in the project root
    3. VITE_CLERK_PUBLISHABLE_KEY environment variable must be set

🔑 Required Environment Variable:
    VITE_CLERK_PUBLISHABLE_KEY - Clerk publishable key (required for build)
    
    To set it, run:
    export VITE_CLERK_PUBLISHABLE_KEY="pk_test_your_key_here"

💡 Examples:
    # Set the required environment variable
    export VITE_CLERK_PUBLISHABLE_KEY="pk_test_xxxxxxxxxxxx"
    
    # Build the Docker image with default timestamp tag
    ./local-docker-test.sh build
    
    # Build with custom tag (will be prompted)
    ./local-docker-test.sh build
    # (Select 'y' when asked, then enter tag like "feature-auth" or "v1.0.0")
    
    # Run the containers with a specific image on default port (7860)
    ./local-docker-test.sh run langflow:localbuild_20241008_120000
    # (Will be prompted for port selection)
    
    # Run the containers (will prompt for image selection and port)
    ./local-docker-test.sh run
    
    # Run multiple instances on different ports
    ./local-docker-test.sh run langflow:feature-auth
    # (Enter port 7860 for first instance)
    ./local-docker-test.sh run langflow:feature-xyz  
    # (Enter port 7861 for second instance)
    
    # Stop containers (interactive menu will be shown)
    ./local-docker-test.sh stop
    # (Choose option 1 to stop all, 2 for default, or 3 for specific port)
    
    # Alternative: Stop specific containers manually
    docker stop langflow-local-test-7861 langflow-postgres-local-7861

🌐 Access:
    Langflow UI:  http://localhost:[YOUR_SELECTED_PORT]
    Postgres DB:  localhost:[AUTO_CALCULATED_PORT] (user: langflow, password: langflow, db: langflow)

🔍 Troubleshooting:
    View container logs:
        docker logs langflow-local-test-[PORT]
        docker logs langflow-postgres-local-[PORT]
    
    Check running containers:
        docker ps
    
    List all Langflow containers:
        docker ps -a | grep langflow
    
    Stop specific instance by port:
        docker stop langflow-local-test-7861 langflow-postgres-local-7861
        docker rm langflow-local-test-7861 langflow-postgres-local-7861

📝 Notes:
    - Multiple instances can run simultaneously on different ports
    - Each instance gets unique container and network names based on the port
    - Postgres port is auto-calculated: 5432 + (Langflow_port - 7860)
      Example: Langflow on 7861 → Postgres on 5433
    - Custom tags help organize builds by feature/branch/version

EOF
}

# Check if VITE_CLERK_PUBLISHABLE_KEY is set
check_clerk_key() {
    if [ -z "${VITE_CLERK_PUBLISHABLE_KEY:-}" ]; then
        echo "❌ Error: VITE_CLERK_PUBLISHABLE_KEY environment variable is not set!"
        echo ""
        echo "🔑 This is a required environment variable for building the Docker image."
        echo ""
        echo "✅ To set it, run:"
        echo "    export VITE_CLERK_PUBLISHABLE_KEY=\"pk_test_your_key_here\""
        echo ""
        echo "📝 Then run the build command again:"
        echo "    $0 build"
        echo ""
        exit 1
    fi
    echo "✅ VITE_CLERK_PUBLISHABLE_KEY is set"
}

# Configuration from GitHub workflow (staging environment)
VITE_AUTO_LOGIN=false
VITE_CLERK_AUTH_ENABLED=true
VITE_CLERK_PUBLISHABLE_KEY="${VITE_CLERK_PUBLISHABLE_KEY:-}"

# Docker image details
IMAGE_NAME="langflow"
IMAGE_TAG="localbuild_$(date +%Y%m%d_%H%M%S)"
CONTAINER_NAME="langflow-local-test"
POSTGRES_CONTAINER="langflow-postgres-local"
NETWORK_NAME="langflow-test-network"

# Postgres configuration
POSTGRES_DB="langflow"
POSTGRES_USER="langflow"
POSTGRES_PASSWORD="langflow"
POSTGRES_PORT="5432"

# Function to build Docker image
build_docker() {
    # Check for required environment variable
    check_clerk_key
    
    # Ask for custom tag
    echo ""
    echo "🏷️  Docker Image Tagging"
    echo "   Default tag will be: localbuild_$(date +%Y%m%d_%H%M%S)"
    read -p "Do you want to use a custom tag for this build? (y/N): " USE_CUSTOM_TAG
    
    if [[ "$USE_CUSTOM_TAG" =~ ^[Yy]$ ]]; then
        # Get current branch name
        CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
        echo ""
        echo "📌 Current branch: ${CURRENT_BRANCH}"
        read -p "Enter custom tag (e.g., ${CURRENT_BRANCH}, v1.0.0, feature-xyz): " CUSTOM_TAG
        
        if [ -n "$CUSTOM_TAG" ]; then
            # Sanitize tag name (replace invalid characters)
            CUSTOM_TAG=$(echo "$CUSTOM_TAG" | sed 's/[^a-zA-Z0-9._-]/_/g')
            IMAGE_TAG="$CUSTOM_TAG"
            echo "✅ Using custom tag: ${IMAGE_TAG}"
        else
            echo "⚠️  Empty tag provided, using default timestamp"
            IMAGE_TAG="localbuild_$(date +%Y%m%d_%H%M%S)"
        fi
    else
        IMAGE_TAG="localbuild_$(date +%Y%m%d_%H%M%S)"
        echo "✅ Using default tag: ${IMAGE_TAG}"
    fi
    
    echo ""
    echo "🔨 Building Docker image with tag: ${IMAGE_NAME}:${IMAGE_TAG}"
    echo ""
    
    TAG="${IMAGE_NAME}:${IMAGE_TAG}" \
    DOCKER_BUILDKIT=1 \
    VITE_AUTO_LOGIN=${VITE_AUTO_LOGIN} \
    VITE_CLERK_AUTH_ENABLED=${VITE_CLERK_AUTH_ENABLED} \
    VITE_CLERK_PUBLISHABLE_KEY=${VITE_CLERK_PUBLISHABLE_KEY} \
    make docker_build
    
    echo ""
    echo "✅ Docker image built successfully"
    echo "📦 Image tag: ${IMAGE_NAME}:${IMAGE_TAG}"
    echo ""
    echo "💡 To run this image, use:"
    echo "   $0 run ${IMAGE_NAME}:${IMAGE_TAG}"
}

# Function to run Docker containers
run_docker() {
    local IMAGE_TO_RUN="${1:-}"
    local IMAGE_NAME="langflow"
    
    # If no image specified, list available images and prompt
    if [ -z "$IMAGE_TO_RUN" ]; then
        echo "📋 Available Langflow images:"
        docker images --filter "reference=${IMAGE_NAME}" --format "   {{.Repository}}:{{.Tag}} (created {{.CreatedSince}})"
        echo ""
        read -p "Enter image tag to run (copy/paste from above, e.g., langflow:1.4.2): " IMAGE_TO_RUN
        
        if [ -z "$IMAGE_TO_RUN" ]; then
            echo "❌ Error: No image tag provided"
            exit 1
        fi
    fi
    
    # Check if image exists
    if ! docker image inspect "$IMAGE_TO_RUN" >/dev/null 2>&1; then
        echo "❌ Error: Image '$IMAGE_TO_RUN' not found"
        echo ""
        echo "Available images:"
        docker images --filter "reference=${IMAGE_NAME}" --format "   {{.Repository}}:{{.Tag}}"
        exit 1
    fi
    
    # Ask for host port
    echo ""
    echo "🔌 Port Configuration"
    read -p "Enter host port for Langflow (default: 7860): " LANGFLOW_HOST_PORT
    LANGFLOW_HOST_PORT=${LANGFLOW_HOST_PORT:-7860}
    
    # Check if port is already in use
    if lsof -Pi :${LANGFLOW_HOST_PORT} -sTCP:LISTEN -t >/dev/null 2>&1 || netstat -an 2>/dev/null | grep -q ":${LANGFLOW_HOST_PORT}.*LISTEN"; then
        echo "⚠️  Warning: Port ${LANGFLOW_HOST_PORT} appears to be in use"
        echo "   This might be another Langflow instance or a different service"
        read -p "   Do you want to continue anyway? (y/N): " CONTINUE_ANYWAY
        if [[ ! "$CONTINUE_ANYWAY" =~ ^[Yy]$ ]]; then
            echo "❌ Aborted. Please choose a different port or stop the service using port ${LANGFLOW_HOST_PORT}"
            exit 1
        fi
    fi
    
    # Use unique container names based on port to allow multiple instances
    local UNIQUE_CONTAINER_NAME="${CONTAINER_NAME}-${LANGFLOW_HOST_PORT}"
    local UNIQUE_POSTGRES_CONTAINER="${POSTGRES_CONTAINER}-${LANGFLOW_HOST_PORT}"
    local UNIQUE_NETWORK_NAME="${NETWORK_NAME}-${LANGFLOW_HOST_PORT}"
    local UNIQUE_POSTGRES_PORT=$((5432 + LANGFLOW_HOST_PORT - 7860))
    
    echo ""
    echo "🚀 Starting Docker containers with image: $IMAGE_TO_RUN"
    echo "🔌 Langflow will be available on port: ${LANGFLOW_HOST_PORT}"
    echo "🗄️  Postgres will be available on port: ${UNIQUE_POSTGRES_PORT}"
    
    # Create network if it doesn't exist
    docker network inspect ${UNIQUE_NETWORK_NAME} >/dev/null 2>&1 || \
        docker network create ${UNIQUE_NETWORK_NAME}
    
    # Start Postgres container
    echo "🗄️  Starting Postgres container..."
    docker run -d \
        --name ${UNIQUE_POSTGRES_CONTAINER} \
        --network ${UNIQUE_NETWORK_NAME} \
        -e POSTGRES_DB=${POSTGRES_DB} \
        -e POSTGRES_USER=${POSTGRES_USER} \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -p ${UNIQUE_POSTGRES_PORT}:5432 \
        postgres:15.4
    
    # Wait for Postgres to be ready
    echo "⏳ Waiting for Postgres to be ready..."
    sleep 5
    
    # Start Langflow container with env-file
    echo "🌊 Starting Langflow container..."
    docker run -d \
        --name ${UNIQUE_CONTAINER_NAME} \
        --network ${UNIQUE_NETWORK_NAME} \
        --env-file .env-file \
        -e LANGFLOW_DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${UNIQUE_POSTGRES_CONTAINER}:5432/${POSTGRES_DB}" \
        -p ${LANGFLOW_HOST_PORT}:7860 \
        ${IMAGE_TO_RUN}
    
    echo ""
    echo "✅ Containers started successfully"
    echo "🌐 Langflow: http://localhost:${LANGFLOW_HOST_PORT}"
    echo "🗄️  Postgres: localhost:${UNIQUE_POSTGRES_PORT}"
    echo "🏷️  Using image: ${IMAGE_TO_RUN}"
    echo "📦 Container: ${UNIQUE_CONTAINER_NAME}"
    echo ""
    echo "💡 To view logs: docker logs ${UNIQUE_CONTAINER_NAME}"
    echo "💡 To stop this instance: docker stop ${UNIQUE_CONTAINER_NAME} ${UNIQUE_POSTGRES_CONTAINER}"
}

# Function to stop Docker containers
stop_docker() {
    echo "🛑 Stopping Docker containers..."
    echo ""
    
    # List all running Langflow-related containers
    echo "📋 Running Langflow containers:"
    LANGFLOW_CONTAINERS=$(docker ps --filter "name=langflow-local-test" --format "{{.Names}}\t{{.Ports}}\t{{.Status}}")
    POSTGRES_CONTAINERS=$(docker ps --filter "name=langflow-postgres-local" --format "{{.Names}}\t{{.Ports}}\t{{.Status}}")
    
    if [ -z "$LANGFLOW_CONTAINERS" ] && [ -z "$POSTGRES_CONTAINERS" ]; then
        echo "   No Langflow containers are currently running"
        return 0
    fi
    
    # Display containers
    if [ -n "$LANGFLOW_CONTAINERS" ]; then
        echo ""
        echo "   Langflow containers:"
        echo "$LANGFLOW_CONTAINERS" | while read line; do
            echo "   - $line"
        done
    fi
    
    if [ -n "$POSTGRES_CONTAINERS" ]; then
        echo ""
        echo "   Postgres containers:"
        echo "$POSTGRES_CONTAINERS" | while read line; do
            echo "   - $line"
        done
    fi
    
    echo ""
    echo "🔧 Stop Options:"
    echo "   1) Stop ALL Langflow containers"
    echo "   2) Stop default containers only (langflow-local-test-7860)"
    echo "   3) Stop specific container by port"
    echo "   4) Cancel"
    echo ""
    read -p "Select option (1-4): " STOP_OPTION
    
    case "$STOP_OPTION" in
        1)
            echo "🛑 Stopping ALL Langflow containers..."
            # Stop all Langflow containers
            docker ps --filter "name=langflow-local-test" --format "{{.Names}}" | xargs -r docker stop 2>/dev/null || true
            docker ps --filter "name=langflow-postgres-local" --format "{{.Names}}" | xargs -r docker stop 2>/dev/null || true
            
            # Remove all Langflow containers
            docker ps -a --filter "name=langflow-local-test" --format "{{.Names}}" | xargs -r docker rm 2>/dev/null || true
            docker ps -a --filter "name=langflow-postgres-local" --format "{{.Names}}" | xargs -r docker rm 2>/dev/null || true
            
            # Remove all Langflow networks
            docker network ls --filter "name=langflow-test-network" --format "{{.Name}}" | xargs -r docker network rm 2>/dev/null || true
            
            echo "✅ All Langflow containers stopped and removed"
            ;;
        2)
            echo "🛑 Stopping default containers..."
            docker stop ${CONTAINER_NAME} 2>/dev/null || true
            docker rm ${CONTAINER_NAME} 2>/dev/null || true
            docker stop ${POSTGRES_CONTAINER} 2>/dev/null || true
            docker rm ${POSTGRES_CONTAINER} 2>/dev/null || true
            docker network rm ${NETWORK_NAME} 2>/dev/null || true
            echo "✅ Default containers stopped and removed"
            ;;
        3)
            read -p "Enter the port number to stop (e.g., 7860, 7861): " PORT_TO_STOP
            if [ -z "$PORT_TO_STOP" ]; then
                echo "❌ No port provided"
                return 1
            fi
            
            SPECIFIC_CONTAINER="${CONTAINER_NAME}-${PORT_TO_STOP}"
            SPECIFIC_POSTGRES="${POSTGRES_CONTAINER}-${PORT_TO_STOP}"
            SPECIFIC_NETWORK="${NETWORK_NAME}-${PORT_TO_STOP}"
            
            echo "🛑 Stopping containers on port ${PORT_TO_STOP}..."
            docker stop ${SPECIFIC_CONTAINER} 2>/dev/null || true
            docker rm ${SPECIFIC_CONTAINER} 2>/dev/null || true
            docker stop ${SPECIFIC_POSTGRES} 2>/dev/null || true
            docker rm ${SPECIFIC_POSTGRES} 2>/dev/null || true
            docker network rm ${SPECIFIC_NETWORK} 2>/dev/null || true
            echo "✅ Containers on port ${PORT_TO_STOP} stopped and removed"
            ;;
        4)
            echo "❌ Cancelled"
            return 0
            ;;
        *)
            echo "❌ Invalid option"
            return 1
            ;;
    esac
}

# Main script logic
case "${1:-}" in
    build)
        build_docker
        ;;
    run)
        run_docker "${2:-}"
        ;;
    stop)
        stop_docker
        ;;
    -h|--help)
        show_help
        ;;
    -v|--verbose)
        show_verbose_help
        ;;
    *)
        echo "❌ Error: Invalid command '${1:-}'"
        echo ""
        echo "Usage: $0 {build|run [IMAGE_TAG]|stop|-h|--help|-v|--verbose}"
        echo ""
        echo "Run '$0 --help' for basic help or '$0 --verbose' for detailed examples"
        exit 1
        ;;
esac
