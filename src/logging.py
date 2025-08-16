import logging


class ProfileFilter(logging.Filter):
    """
    Custom filter that allows to seperate profiling logging from general-purpose logging
    """
    def __init__(self, is_profile: bool):
        self.is_profile = is_profile

    def filter(self, record: logging.LogRecord) -> bool:
        if "PERF" in record.msg:
            return self.is_profile
        else:
            return not self.is_profile

