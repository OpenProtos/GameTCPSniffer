from logging import Logger
import time

import pyinstrument
from typing import Any, Callable, Optional

from attrs import define, field


@define
class AsyncProfiler:
    logger: Logger
    _profiler: Optional[pyinstrument.Profiler] = field(default=None, init=False)
    _threshold_ms: float = field(default=50.0)

    async def profile(self, name: str, func: Callable[[Any], Any], *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()

        try:
            if self._profiler is None:
                self._profiler = pyinstrument.Profiler(async_mode="enabled")
                self._profiler.start()

            result = func(*args, **kwargs)
            return result

        finally:
            duration = (time.perf_counter() - start) * 1000
            profile = None

            if self._profiler is not None:
                self._profiler.stop()
                profile = self._profiler.output(pyinstrument.renderers.ConsoleRenderer())
                self._profiler = None

            self._log_performance(name, duration, profile)


    def _log_performance(self, name: str, duration: float, profile: Optional[str] = None) -> None:
        entry = {
            "operation": name,
            "duration_ms": round(duration, 2),
            "threshold": self._threshold_ms,
        }

        if duration > self._threshold_ms:
            self.logger.warning(f"PERF: {entry}")
            self.logger.warning(f"PERF: {profile}")

