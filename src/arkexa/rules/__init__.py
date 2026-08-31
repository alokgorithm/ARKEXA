"""Rule modules. Importing this package registers every rule."""

from . import (  # noqa: F401
    ark001_untrusted_prompt_write_token,
    ark002_agent_output_to_shell,
    ark003_agent_output_to_path,
    ark004_agent_autoapprove,
    ark005_agent_writes_default_branch,
)
