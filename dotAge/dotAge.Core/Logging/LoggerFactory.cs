using Microsoft.Extensions.Logging;

namespace DotAge.Core.Logging;

/// <summary>
///     Factory for creating loggers in DotAge.Core.
/// </summary>
public static class LoggerFactory
{
    private static ILoggerFactory? _loggerFactory;

    /// <summary>
    ///     Gets or sets the logger factory instance.
    /// </summary>
    public static ILoggerFactory Instance
    {
        get
        {
            if (_loggerFactory != null)
                return _loggerFactory;

            _loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
            {
                builder.ClearProviders();
#if DEBUG
                builder.AddProvider(new FilteredConsoleLoggerProvider());
                var logFilePath = Environment.GetEnvironmentVariable("DOTAGE_LOG_FILE") ?? "dotage-debug.log";
                builder.AddProvider(new FileLoggerProvider(logFilePath));
#endif
            });
            return _loggerFactory;
        }
    }

    /// <summary>
    ///     Creates a logger for the specified type.
    /// </summary>
    /// <typeparam name="T">The type to create a logger for.</typeparam>
    /// <returns>A logger instance.</returns>
    public static ILogger<T> CreateLogger<T>()
    {
        return Instance.CreateLogger<T>();
    }

    /// <summary>
    ///     Creates a logger with the specified category name.
    /// </summary>
    /// <param name="categoryName">The category name for the logger.</param>
    /// <returns>A logger instance.</returns>
    public static ILogger CreateLogger(string categoryName)
    {
        return Instance.CreateLogger(categoryName);
    }
}

/// <summary>
///     Console logger provider that filters out Trace and Debug messages.
/// </summary>
public class FilteredConsoleLoggerProvider : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName)
    {
        return new FilteredConsoleLogger(categoryName);
    }

    public void Dispose()
    {
        // Nothing to dispose
    }
}

/// <summary>
///     Console logger that filters log levels based on environment variable configuration.
/// </summary>
public class FilteredConsoleLogger : ILogger
{
    private readonly string _categoryName;
    private readonly LogLevel _minimumLogLevel;

    public FilteredConsoleLogger(string categoryName)
    {
        _categoryName = categoryName;
        _minimumLogLevel = GetMinimumLogLevel();
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return null;
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return logLevel >= _minimumLogLevel;
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;

        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var level = logLevel.ToString().ToUpperInvariant();
        var message = formatter(state, exception);
        var logEntry = $"{timestamp} [{level}] {_categoryName}: {message}";

        Console.WriteLine(logEntry);
    }

    private static LogLevel GetMinimumLogLevel()
    {
        var logLevelString = Environment.GetEnvironmentVariable("DOTAGE_LOG_LEVEL");
        if (string.IsNullOrEmpty(logLevelString))
            return LogLevel.Information; // Default to Information

        return logLevelString.ToUpperInvariant() switch
        {
            "TRACE" => LogLevel.Trace,
            "DEBUG" => LogLevel.Debug,
            "INFORMATION" => LogLevel.Information,
            "WARNING" => LogLevel.Warning,
            "ERROR" => LogLevel.Error,
            "CRITICAL" => LogLevel.Critical,
            "NONE" => LogLevel.None,
            _ => LogLevel.Information // Default fallback
        };
    }
}

/// <summary>
///     Simple file logger provider that writes all log levels to a file.
/// </summary>
public class FileLoggerProvider : ILoggerProvider
{
    private readonly string _filePath;
    private readonly object _lock = new();

    public FileLoggerProvider(string filePath)
    {
        _filePath = filePath;
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new FileLogger(_filePath, categoryName, _lock);
    }

    public void Dispose()
    {
        // Nothing to dispose
    }
}

/// <summary>
///     Simple file logger that writes all log levels to a file.
/// </summary>
public class FileLogger : ILogger
{
    private readonly string _categoryName;
    private readonly string _filePath;
    private readonly object _lock;

    public FileLogger(string filePath, string categoryName, object lockObj)
    {
        _filePath = filePath;
        _categoryName = categoryName;
        _lock = lockObj;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return null;
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return true; // Allow all log levels
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        lock (_lock)
        {
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            var level = logLevel.ToString().ToUpperInvariant();
            var message = formatter(state, exception);
            var logEntry = $"{timestamp} [{level}] {_categoryName}: {message}";

            File.AppendAllText(_filePath, logEntry + Environment.NewLine);
        }
    }
}