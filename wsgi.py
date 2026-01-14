from task_manager import create_app

app = create_app()

# For some WSGI servers that prefer app variable
if __name__ == '__main__':
    app.run()
