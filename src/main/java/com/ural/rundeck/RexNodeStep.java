package com.ural.rundeck;

import com.dtolabs.rundeck.core.execution.workflow.steps.node.NodeStepException;
import com.dtolabs.rundeck.core.execution.workflow.steps.node.NodeStepFailureReason;
import com.dtolabs.rundeck.core.execution.workflow.steps.FailureReason;
import com.dtolabs.rundeck.core.execution.workflow.steps.StepFailureReason;
import com.dtolabs.rundeck.core.execution.service.NodeExecutorResultImpl;
import com.dtolabs.rundeck.core.plugins.Plugin;
//import com.dtolabs.rundeck.core.plugins.configuration.Describable;
//import com.dtolabs.rundeck.core.plugins.configuration.Description;
import com.dtolabs.rundeck.core.plugins.configuration.PropertyScope;
//import com.dtolabs.rundeck.core.plugins.configuration.PropertyUtil;
import com.dtolabs.rundeck.plugins.ServiceNameConstants;
import com.dtolabs.rundeck.plugins.descriptions.PluginDescription;
import com.dtolabs.rundeck.plugins.descriptions.PluginProperty;
import com.dtolabs.rundeck.plugins.step.PluginStepContext;
import com.dtolabs.rundeck.plugins.step.NodeStepPlugin;
import com.dtolabs.rundeck.core.utils.OptsUtil;
import com.dtolabs.rundeck.core.utils.ScriptExecUtil;
import com.dtolabs.rundeck.core.dispatcher.DataContextUtils;
import com.dtolabs.rundeck.core.common.INodeEntry;
import com.dtolabs.rundeck.core.common.INodeSet;

import java.util.*;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;


@Plugin(name = RexNodeStep.SERVICE_PROVIDER_NAME, service = ServiceNameConstants.WorkflowNodeStep)
@PluginDescription(title = "Rex Step", description = "Запускает задачи (R)?ex на узле.\nАдрес узла передается параметром -H. Имя пользователя передается параметром -u.\nРаспределением по узлам управляет Rundeck.")
public class RexNodeStep implements NodeStepPlugin {
  public static final String SERVICE_PROVIDER_NAME = "com.ural.rundeck.RexNodeStep";

  private static final String rex_cmd = "rex";

  // Properties
  //@PluginProperty(title = "Rex Exe", description = "Rex executable", required = true, defaultValue = "rex")
  //private String rex_exe;

  @PluginProperty(title = "Rex Task", description = "Имя задачи Rex, см. вывод rex -T", required = true)
  private String task;

  @PluginProperty(title = "Arguments", description = "Аргументы, передаваемые задаче Rex в формате: --parameter1=value1 --parameter2=value2")
  private String args;

  @PluginProperty(title = "Rex Arguments", description = "Дополнительные аргументы команды rex, см. man rex")
  private String rex_args;

  @PluginProperty(title = "Rexfile Directory", description = "Каталог с Rexfile", required = true,
    defaultValue = "/var/www/net/rexrepo", scope = PropertyScope.Project)
  private String rexrepo_dir;
  @PluginProperty(title = "Override Rexfile Dir", description = "Использовать этот каталог с Rexfile вместо установленного глобальными настройками")
  private String rexrepo_dir_override;


  public enum RexExecReason implements FailureReason {
    NonZeroResultCode, // rex command exited with non-zero value
    RexError, // rex not found etc.
    Unknown
  }

  public interface LocalRexRunner {
    int runLocalCommand(
      final String[] command,
      final Map<String, String> envMap,
      final File workingdir,
      final OutputStream outputStream,
      final OutputStream errorStream
    ) throws IOException, InterruptedException;
  }

  private static class UtilRunner implements LocalRexRunner {
    @Override
    public int runLocalCommand(
      final String[] command,
      final Map<String, String> envMap,
      final File workingdir,
      final OutputStream outputStream,
      final OutputStream errorStream
    ) throws IOException, InterruptedException {
      return ScriptExecUtil.runLocalCommand(command, envMap, workingdir, outputStream, errorStream);
    }
  }

  private LocalRexRunner runner = new UtilRunner();


  @Override
  public void executeNodeStep(final PluginStepContext context, final Map<String, Object> configuration, INodeEntry entry)
    throws NodeStepException {
   
    if (rexrepo_dir == null || rexrepo_dir.isEmpty()) {
      throw new NodeStepException("Rex Directory is not set", StepFailureReason.ConfigurationFailure, entry.getNodename());
    }
    //override rex directory
    if (rexrepo_dir_override != null && rexrepo_dir_override.length() > 0) {
      rexrepo_dir = rexrepo_dir_override;
    }

    if (task == null || task.isEmpty()) {
      throw new NodeStepException("Rex Task Name is not set", StepFailureReason.ConfigurationFailure, entry.getNodename());
    }

    Map<String, Map<String, String>> node_data = DataContextUtils.addContext("node",
      DataContextUtils.nodeData(entry),
      context.getDataContext());

    final List<String> cmd_list = new ArrayList<>();
    cmd_list.add(rex_cmd);
    //cmd_list.add("-m");
    // rex arguments
    if (rex_args != null  && rex_args.length() > 0) {
      String[] raa = DataContextUtils.replaceDataReferences(OptsUtil.burst(rex_args), node_data);
      cmd_list.addAll(Arrays.asList(raa));
    }
    //user
    cmd_list.add("-u");
    cmd_list.add(entry.getUsername());
    //node
    cmd_list.add("-H");
    cmd_list.add(entry.getHostname());
    // task
    String ta = DataContextUtils.replaceDataReferences(task, node_data);
    cmd_list.add(ta);
    // task arguments
    if (args != null && args.length() > 0) {
      String[] aa = DataContextUtils.replaceDataReferences(OptsUtil.burst(args), node_data);
      cmd_list.addAll(Arrays.asList(aa));
    }

    final String[] finalCommand = cmd_list.toArray(new String[0]);
    //debug
    StringBuilder preview = new StringBuilder();
    for (int i=0; i<finalCommand.length; i++) {
      preview.append("'").append(finalCommand[i]).append("'");
    }
    context.getLogger().log(5, "RexNodeStep, running command ("+cmd_list.size()+"): "+preview.toString());
    Map<String, String> env = DataContextUtils.generateEnvVarsFromContext(node_data);

    final int result;
    try {
      result = runner.runLocalCommand(finalCommand, env, rexrepo_dir.isEmpty() ? null:new File(rexrepo_dir), System.out, System.err);
      if (result != 0) {
	Map<String, Object> failure_data = new HashMap<>();
	failure_data.put(NodeExecutorResultImpl.FAILURE_DATA_RESULT_CODE, result);
	throw new NodeStepException("Result code was " + result,
	  NodeStepFailureReason.NonZeroResultCode,
	  failure_data,
	  entry.getNodename());
      }
    } catch (IOException e) {
      throw new NodeStepException(e, StepFailureReason.IOFailure, entry.getNodename());
    } catch (InterruptedException e) {
      throw new NodeStepException(e, StepFailureReason.Interrupted, entry.getNodename());
    }
  }
}

