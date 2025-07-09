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

#if DEBUG
            _loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
            {
                builder.AddConsole().SetMinimumLevel(LogLevel.Trace);
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