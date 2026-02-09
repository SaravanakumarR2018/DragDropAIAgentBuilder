class _ErrorMessagesSingleton:
    _instance = None

    def __new__(cls) -> "_ErrorMessagesSingleton":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self.paddle_customer_already_exist_message = "customer email conflicts with customer of id"
        self._initialized = True


error_messages = _ErrorMessagesSingleton()