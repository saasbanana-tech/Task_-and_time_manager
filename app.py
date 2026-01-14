from task_manager import create_app

# Lightweight launcher for development
app = create_app()

if __name__ == '__main__':
    # Do not enable debug True in production
    app.run(debug=True)
