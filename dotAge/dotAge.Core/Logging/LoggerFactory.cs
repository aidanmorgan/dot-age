using Microsoft.Extensions.Logging;
using System.IO;

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

#if DEBUG
            _loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
            {
                // Console logging - only Info and above
                builder.AddConsole(options =>
                {
                    options.IncludeScopes = false;
                })
                .SetMinimumLevel(LogLevel.Information);

                // File logging - all levels including Trace
                builder.AddProvider(new FileLoggerProvider("dotage-stress.log"));
            });
#else
            _loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder => { });
#endif
            return _loggerFactory;
        }
        set => _loggerFactory = value;
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
///     Simple file logger provider that writes all log levels to a file.
/// </summary>
public class FileLoggerProvider : ILoggerProvider
{
    private readonly string _filePath;
    private readonly object _lock = new object();

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
    private readonly string _filePath;
    private readonly string _categoryName;
    private readonly object _lock;

    public FileLogger(string filePath, string categoryName, object lockObj)
    {
        _filePath = filePath;
        _categoryName = categoryName;
        _lock = lockObj;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
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