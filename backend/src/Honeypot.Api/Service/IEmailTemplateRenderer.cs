using Honeypot.Api.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface IEmailTemplateRenderer
{
    RenderedEmail RenderTest(DateTimeOffset now);
    RenderedEmail RenderReport(string kind, OperationReport report);
}
