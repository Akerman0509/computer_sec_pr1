class FolderBasedRouter:
    def db_for_read(self, model, **hints):
        module = model.__module__
        # print(f"[db_for_read] Model: {model.__name__}, Module: {module}")
        
        if module.startswith("my_app."):
            return "default"
        elif module.startswith("my_DB1."):
            return "job_db"
        elif module.startswith(("myModels.model1.", "myModels.model2.")):
            return "custom_db"
        else:
            # print(f"[db_for_read] No matching database found for model: {model.__name__}")
            return "default"

    def db_for_write(self, model, **hints):
        module = model.__module__
        # print(f"[db_for_write] Model: {model.__name__}, Module: {module}")

        if module.startswith("my_app."):
            return "default"
        elif module.startswith("my_DB1."):
            return "job_db"
        elif module.startswith(( "myModels.model1.", "myModels.model2.")):
            return "custom_db"
        else:
            # print(f"[db_for_write] No matching database found for model: {model.__name__}")
            return "default"
