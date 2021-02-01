package com.ural.rundeck;

import com.dtolabs.rundeck.core.execution.workflow.steps.StepException;
import com.dtolabs.rundeck.core.execution.workflow.steps.FailureReason;
import com.dtolabs.rundeck.core.execution.workflow.steps.StepFailureReason;
import com.dtolabs.rundeck.core.plugins.Plugin;
//import com.dtolabs.rundeck.core.plugins.configuration.Describable;
//import com.dtolabs.rundeck.core.plugins.configuration.Description;
import com.dtolabs.rundeck.core.plugins.configuration.PropertyScope;
//import com.dtolabs.rundeck.core.plugins.configuration.PropertyUtil;
import com.dtolabs.rundeck.plugins.ServiceNameConstants;
import com.dtolabs.rundeck.plugins.descriptions.PluginDescription;
import com.dtolabs.rundeck.plugins.descriptions.PluginProperty;
import com.dtolabs.rundeck.plugins.step.PluginStepContext;
import com.dtolabs.rundeck.plugins.step.StepPlugin;
import com.dtolabs.rundeck.core.utils.OptsUtil;
import com.dtolabs.rundeck.core.utils.ScriptExecUtil;
import com.dtolabs.rundeck.core.dispatcher.DataContextUtils;
import com.dtolabs.rundeck.core.common.INodeEntry;
import com.dtolabs.rundeck.core.common.INodeSet;

import java.util.*;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;


@Plugin(name = RexWorkflowStep.SERVICE_PROVIDER_NAME, service = ServiceNameConstants.WorkflowStep)
@PluginDescription(title = "Rex Step", description = "Запускает задачи (R)?ex на узлах.\nСписок узлов передается параметром -Н. Имена пользователей не передаются.\nРаспределением по узлам управляет Rex.")
public class RexWorkflowStep implements StepPlugin {
  public static final String SERVICE_PROVIDER_NAME = "com.ural.rundeck.RexWorkflowStep";

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
  public void executeStep(final PluginStepContext context, final Map<String, Object> configuration)
    throws StepException {
   
    if (rexrepo_dir == null || rexrepo_dir.isEmpty()) {
      throw new StepException("Rex Directory is not set", StepFailureReason.ConfigurationFailure);
    }
    //override rex directory
    if (rexrepo_dir_override != null && rexrepo_dir_override.length() > 0) {
      rexrepo_dir = rexrepo_dir_override;
    }

    if (task == null || task.isEmpty()) {
      throw new StepException("Rex Task Name is not set", StepFailureReason.ConfigurationFailure);
    }

    final List<String> limits = new ArrayList<>();
    for (INodeEntry ine : context.getNodes()) {
      limits.add(ine.getHostname());
    }

    final List<String> cmd_list = new ArrayList<>();
    cmd_list.add(rex_cmd);
    //cmd_list.add("-m");
    // rex arguments
    if (rex_args != null  && rex_args.length() > 0) {
      String[] raa = DataContextUtils.replaceDataReferences(OptsUtil.burst(rex_args), context.getDataContext());
      cmd_list.addAll(Arrays.asList(raa));
    }
    // nodes
    if (limits.size() > 0) {
      cmd_list.add("-H");
      StringBuilder sb = new StringBuilder("");
      sb.append(DataContextUtils.join(limits, " "));
      //sb.append("\"");
      cmd_list.add(sb.toString());
    }
    // task
    String ta = DataContextUtils.replaceDataReferences(task, context.getDataContext());
    cmd_list.add(ta);
    // task arguments
    if (args != null && args.length() > 0) {
      String[] aa = DataContextUtils.replaceDataReferences(OptsUtil.burst(args), context.getDataContext());
      cmd_list.addAll(Arrays.asList(aa));
    }

    final String[] finalCommand = cmd_list.toArray(new String[0]);
    //debug
    StringBuilder preview = new StringBuilder();
    for (int i=0; i<finalCommand.length; i++) {
      preview.append("'").append(finalCommand[i]).append("'");
    }
    context.getLogger().log(5, "RexWorkflowStep, running command ("+cmd_list.size()+"): "+preview.toString());
    Map<String, String> env = DataContextUtils.generateEnvVarsFromContext(context.getDataContext());

    final int result;
    try {
      result = runner.runLocalCommand(finalCommand, env, rexrepo_dir.isEmpty() ? null:new File(rexrepo_dir), System.out, System.err);
      if (result != 0) {
	throw new StepException("Result code was " + result,
	  RexExecReason.NonZeroResultCode);
      }
    } catch (IOException e) {
      throw new StepException(e, StepFailureReason.IOFailure);
    } catch (InterruptedException e) {
      throw new StepException(e, StepFailureReason.Interrupted);
    }

    //System.out.println("Example step executing on nodes: " + context.getNodes().getNodeNames());
    //System.out.println("Example step configuration: " + configuration);
    //System.out.println("Example step num: " + context.getStepNumber());
    //System.out.println("Example step context: " + context.getStepContext());
  }
}
