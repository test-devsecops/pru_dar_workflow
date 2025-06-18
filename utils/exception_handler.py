import requests
import time

class ExceptionHandler:
    @staticmethod
    def handle_exception(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.HTTPError as err:
                print("HTTP Error:", err)
                return None
            except requests.exceptions.RequestException as e:
                print(f"RequestException error occurred: {e}")
                return None
            except Exception as err:
                print("An unexpected error occurred:", err)
                return None
        return wrapper
    
    @staticmethod
    def handle_exception_with_retries(logger=None, retries=3, delay=2):
        def decorator(func):
            def wrapper(*args, **kwargs):
                attempt = 0
                while attempt < retries:
                    try:
                        return func(*args, **kwargs)
                    except requests.exceptions.HTTPError as err:
                        msg = f"HTTP Error: {err}"
                    except requests.exceptions.RequestException as err:
                        msg = f"RequestException error occurred: {err}"
                    except Exception as err:
                        msg = f"An unexpected error occurred: {err}"
                    else:
                        break

                    attempt += 1
                    if logger:
                        logger.error(f"{msg} | Retry {attempt}/{retries}")
                        print(f"{msg} | Retry {attempt}/{retries}")
                    else:
                        print(f"{msg} | Retry {attempt}/{retries}")

                    if attempt < retries:
                        time.sleep(delay)
                return None
            return wrapper
        return decorator