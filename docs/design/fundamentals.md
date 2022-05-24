# v2 Fundamentals

In this document:
- ☑️ means implemented in the PoC
- 🔴 means downstream (OCP) only

## Changes since the demo

### ☑️ From cluster-scoped to namespaced
It is desirable for users (e.g. GPU Operator) to set an `ownerReference` on the `Modules` that they own.

Only namespaced resources offer this feature, so `Module` is now namespaced.
This brings additional benefits:
- `DaemonSets` and build objects will always be created in the `Module`'s namespace;
- build `Secrets` will always belong to the `Module`'s namespace;
- no risk that the operator is leveraged to create resources with powerful service accounts in powerful namespaces.

We still make it clear that the `Role` that allows service accounts to create `Modules` should be granted with caution.

### ☑️ Mounting volumes by default
The DriverContainer pod / container mounts the host's `/lib/modules` and `/usr/lib/modules` (in most cases, a symlink)
directories in read-only mode.  
This allows OOT kernel modules in the DriverContainer to depend on RHEL in-tree modules without having to copy them into
the image.  
A direct consequence is that users must place their module files somewhere else in the container filesystem, e.g. under
`/opt/lib/modules`.

The device plugin pod / container mounts the host's `/var/lib/kubelet/device-plugins` in read-write mode.
This is a [requirement](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/#device-plugin-implementation)
for device plugins.

For both pods, additional volumes and volume mounts may be specified as desired.

## Feedback from design meetings

### Secure Boot and module signing
Assumptions:
- we are focusing on signing kmods only;
- we might sign pre-built modules that are already signed (appending a signature to the one that already exists);
- the signing feature should be independent from the build feature;
- the signature format is well-defined and does not depend on the distribution.

A modified `.spec.driverContainer` section could look like the following:
```yaml
driverContainer:
  build: {} # might be overridden per-mapping

  kernelMappings:
    # example mapping
    - literal: 5.16.11-200.fc35.x86_64
      containerImage: quay.io/vendor/module-sample:fedora-5.16.11-200.fc35.x86_64

  sign:
    unsignedImage:
      name: registry.com/vendor/driver:v1-unsigned
    signedImage:
      name: registry.com/vendor/driver:v1-signed
      # or signedImage: ${CONTAINER_IMAGE}, replaced at runtime with the target image corresponding to the kernel mapping
      pushSecretRef: # reference to a secret containing a push secret for registry.com (optional)
    keySecret: # reference to a secret containing the private key
    certSecret: # reference to a secret containing the public key
    filesToSign:
      - /path/to/module0.ko
      - /path/to/module1.ko
```

The operator would create a Job in the cluster that would:
- pull `unsignedImage.name`;
- extract the modules listed in `filesToSign`;
- sign them using the specified key and certificate;
- repack the image and push it to `signedImage.name`.

Creating a separate Job removes the constraint of having ELF signing tools / code in the SRO image.
The operator focuses on the reconciliation loop only.

Tools like [umoci](https://umo.ci/) might help us modify images as desired.

**Proposal**: To implement this feature with support for Kubernetes secrets only (for now).

### Pre-flight checks
Pre-flight checks consist in adding a dedicated CR specifying a future kernel `K` to the cluster.
The traditional reconciliation loop should run just like if a node running `K` was in the cluster.

Assumptions:
- if in-cluster builds are configured for `K` and the resulting image does not exist, the operator should build the
  image;
- if module signing is configured and the resulting image does not exist, the operator should produce an image and push
  it to the desired location;
- the operator should not create DaemonSets.

**Proposal**:
- the `Preflight` CRD should contain a kernel version and a set of labels;

There is no consensus on whether a `Preflight` object should push images.
Some team members would prefer a distinct CRD, while others advocate for adding a boolean to `Preflight`.

**Action items**:
- [ ] Call for a meeting with an architecture lead to decide on the strategy for image builds and pushes in pre-flight
  mode.

### Hub & Spoke setups
Assumptions:
- the operator only handles day 1 situations;
- a mechanism to manage resources on the Spokes from the Hub is available (OCM / 🔴 ACM);
- Spokes may not build images.

**Proposal**:
- run the operator in all spokes;
- deploy the `Module` from the Hub;
- leverage the Pre-flight feature to pre-build and pre-sign images on the Hub;
- add a controller that replicates the Hub's `Module` into an ACM `Policy`, removing all build settings;
- add a build or runtime option to disable features on Spokes and keep the footprint as small as possible.

This proposal is entirely decoupled from the OCM implementation and thus not downstream-specific.

### Logging and troubleshooting
Assumptions:
- Structured logging is desirable;
- The operator must follow community and OCP guidelines;
- User must be able to increase the logging verbosity.

Per [SIG Instrumentation](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md#logging-in-kubernetes):
> Kubernetes project uses [klog](https://github.com/kubernetes/klog) for logging

**Proposal**:
- We use the [`logr` API](https://github.com/go-logr/logr) and the [klog](https://github.com/kubernetes/klog)
  implementation;
- Errors are always returned and optionally wrapped for more context;
- Errors are returned from `Reconcile` and the manager is in charge of logging them and requeueing the request;
- Reusable code (in `pkg`) tries very hard not to log anything;
- Internal code receives and forwards loggers via `context.Context`;
- 🔴 [must-gather](https://docs.openshift.com/container-platform/4.10/support/gathering-cluster-data.html) is
  implemented;
  - no code to be added to SRO; we should instead provide a
    [must-gather image](https://docs.google.com/document/d/18DLxJeq1cQ6oBcNXTkGgUbBiZt5BTamFzORnm6hRrm4/edit?skip_itp2_check=true&pli=1).
- We study the use of [`Events`](https://www.cncf.io/blog/2020/12/10/the-top-kubernetes-apis-for-cloud-native-observability-part-1-the-kubernetes-metrics-service-container-apis-3/)
  to expose troubleshooting data to the user.

## Other fundamentals

### Two DaemonSets per `Module`
DriverContainer and device plugin should be two distinct DaemonSets.
This allows updates to the device plugin spec without driver downtime.

```yaml
apiVersion: ooto.sigs.k8s.io/v1alpha1
kind: Module
metadata:
  name: module-sample
spec:
  devicePlugin: # is a Container spec
    container:
      # This container will be privileged and will mount
      # /var/lib/kubelet/device-plugins automatically.
      image: some-image
      volumeMounts: [] # additional volume mounts (optional)

    serviceAccountName: some-sa # optional
    volumes: [] # a list of additional volumes
  driverContainer: # is a Container spec
    # This container will not be privileged by default.
    # It will mount /lib/modules and /usr/lib/modules automatically.
    container:
      securityContext:
        capabilities:
          add: [SYS_MODULE] # this is enough in most cases
        seLinuxOptions:
          type: spc_t # probably over-privileged, we should look for something tighter
      volumeMounts: [] # additional volume mounts (optional)

    kernelMappings: []
      - literal: 5.16.11-200.fc35.x86_64
        containerImage: quay.io/vendor/module-sample:fedora-5.16.11-200.fc35.x86_64

    serviceAccountName: some-sa # optional
    volumes: [] # a list of additional volumes
  selector:  # top-level selector
    feature.node.kubernetes.io/cpu-cpuid.VMX: true
```

`.spec.driverContainer` and `.spec.devicePlugin` will look like `PodSpec` objects to be extensible in the future with
(init-)containers and other properties if needed.

**Proposal**: to split the existing DaemonSet into two.

### PodSecurityPolicy and service accounts
[Pod Security Policies](https://kubernetes.io/docs/concepts/security/pod-security-policy/) provide an access-control
mechanism that restricts what kind of workload specific accounts can run, among other things.
Although it is an optional feature in Kubernetes, most distribution enable PSPs by default (with the notable exception
of Minikube).

🔴 OCP uses [SecurityContextConstraints](https://docs.openshift.com/container-platform/4.10/authentication/managing-security-context-constraints.html)
instead of PSPs, although both mechanisms are very similar.

The operator creates workload with high privileges:
- `CAP_SYS_MODULE` and some powerful SELinux type for the DriverContainer;
- `privileged: true` for the device-plugin.

Thus, when creating the DaemonSets, we need to set a `.spec.template.spec.serviceAccountName` value that is able to
use a PSP or SCC that will allow the creation of pods.
There are two scenarios:
- either the user supplies both a PSP / SCC and a ServiceAccount that can use it (implemented), or;
- the operator must dynamically two service accounts (one per DaemonSet) and bind them to the appropriate PSPs / SCCs.
  If the default policies are too restrictive or permissive for our most common use case, we might deploy our own in
  the bundle.

**Proposal**: to create one Service Account per DaemonSet and bind it to the appropriate PSP / SCC.

### Conditions vs concrete data
The usage of conditions and the kind of data that they should expose is not consistent across Kubernetes projects.
It seems pretty clear, however, that they should not represent a transient state (`Progressing`, for example, should be
avoided).

`DaemonSets` in Minikube do not expose any condition.
Instead, they expose integers describing extensively the number of daemon pods deployed or scheduled.

Exposing concrete data helps our users better understand the current state of the `Module` and require less difficult
decisions on our side (should we be `Ready` if all pods are running except one?).

**Proposal**: to only expose integers read from the `Modules`' `DaemonSets` (for now).

### ValidatingWebhook for `Module`
We can specify a number of field constraints using OpenAPI in the CRD - `isValidRegex` is not one of them.

The operator should offer a webhook that is triggered on `Module` creation and updates to verify that the regexes
(potentially) present in the kernel mappings are valid.

**Proposal**: to implement a ValidatingWebhook to verify that regexes are valid.

### Templating

To avoid repetition in the CRD, it is desirable to perform variable substitution in select fields of the CRD.
Variables could include:

| Variable                 | Description                                       | Example                         |
|--------------------------|---------------------------------------------------|---------------------------------|
| `${KERNEL_FULL_VERSION}` | Kernel version as reported by the kubelet         | `4.18.0-348.23.1.el8_5.x86_64`  |
| `${KERNEL_XYZ}`          | Kernel version                                    | `4.18.0`                        |
| `${KERNEL_X}`            | Kernel major version                              | `4`                             |
| `${KERNEL_Y}`            | Kernel minor version                              | `18`                            |
| `${KERNEL_Z}`            | Kernel patch version                              | `0`                             |
| `${CONTAINER_IMAGE}`     | The container image determined set in the mapping | `registry.com/vendor/driver:v1` |

#### RHEL specific variables

| Variable                 | Description                            | Example          |
|--------------------------|:---------------------------------------|------------------|
| `${KERNEL_RHEL_VERSION}` | RHEL version this kernel was built for | `el8_5`          |
| `${KERNEL_RHEL_RELEASE}` | Kernel release                         | `348.23.1.el8_5` |
| `${KERNEL_RHEL_ARCH}`    | Kernel architecture                    | `x86_64`         |

#### Debian specific variables

Example version: `5.10.0-13-amd64`

| Variable                   | Description    | Example |
|----------------------------|----------------|---------|
| `${KERNEL_DEBIAN_RELEASE}` | Kernel release | `104`   |
| `${KERNEL_DEBIAN_FLAVOR}`  | Kernel flavor  | `amd64` |

#### Ubuntu specific variables

Example version: `5.4.0-104-generic`

| Variable                   | Description    | Example                 |
|----------------------------|----------------|-------------------------|
| `${KERNEL_UBUNTU_RELEASE}` | Kernel release | `104`                   |
| `${KERNEL_UBUNTU_FLAVOR}`  | Kernel flavor  | `generic`, `aws`, `gke` |

**Proposal**: to parse the kernel version as reported by the kubelet and make it available in select fields:
- all image references
- as default build arguments in the Dockerfiles

## Updated CRD

```yaml
apiVersion: ooto.sigs.k8s.io/v1alpha1
kind: Module
metadata:
  name: module-sample
spec:
  devicePlugin: # resembles a PodSpec
    container:
      # This container will be privileged and will mount
      # /var/lib/kubelet/device-plugins automatically.
      image: some-image
      volumeMounts: [] # additional volume mounts (optional)

    imagePullSecrets:
      - name: pull-secret-0

    serviceAccountName: some-sa # optional
    volumes: [] # a list of additional volumes
  driverContainer: # resembles a PodSpec
    # This container will not be privileged by default.
    # It will mount /lib/modules and /usr/lib/modules automatically.
    container:
      securityContext:
        capabilities:
          add: [SYS_MODULE] # this is enough in most cases
        seLinuxOptions:
          type: spc_t # probably over-privileged, we should look for something tighter
      volumeMounts: [ ] # additional volume mounts (optional)

      build:
        buildArgs:
        - name: SOME_AWS_KEY
          value: SOME_AWS_VALUE
        pull:
          insecure: false
        push:
          insecure: false
          name: '${CONTAINER_IMAGE}'
        dockerfile: |
          FROM some-image
          RUN some-command

      containerImage: ghcr.io/vendor/driver:v1.2.3-${KERNEL_FULL_VERSION}

      kernelMappings:
        - regexp: '^.+\.el8\.x86_64$'

        - literal: 5.16.11-200.fc35.x86_64
          containerImage: ghcr.io/vendor/driver:v1.2.3-${KERNEL_VERSION}-random-suffix

        - regexp: '^.+\-azure'
          build: {} # Build using the top-level settings

        - regexp: '^.+\-aws$'
          build:
            buildArgs:
              - name: SOME_AWS_KEY
                value: SOME_AWS_VALUE
          containerImage: quay.io/vendor/module-sample:aws

        - regexp: '^.+\-gke$'
          build:
            dockerfile: |
              FROM some-new-image
              RUN some-other-command
            push:
              insecure: false
              name: ghcr.io/vendor/driver:v1.2.3-${KERNEL_VERSION}-unsigned
          sign: # GKE COS mandates kernel module signing
            unsignedImage:
              name: ghcr.io/vendor/driver:v1.2.3-${KERNEL_VERSION}-unsigned
            signedImage:
              name: ${CONTAINER_IMAGE}
            keySecret: # reference to a secret containing the private key
            certSecret: # reference to a secret containing the public key
            filesToSign:
              - /path/to/module0.ko
              - /path/to/module1.ko

    imageRepoSecrets: # used as imagePullSecrets in the DaemonSet and to pull / push for the build and sign features
      - name: pull-secret-0
      - name: pull-secret-1

    serviceAccountName: some-sa # optional
    volumes: [] # a list of additional volumes
  selector:  # top-level selector
    feature.node.kubernetes.io/cpu-cpuid.VMX: true
status:
  devicePlugin:
    # The total number of nodes that should be running the daemon
    # pod (including nodes correctly running the daemon pod).
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/
    desiredNumberScheduled: 1

    # The number of nodes that should be running the daemon pod and have one
    # or more of the daemon pod running with a Ready Condition.
    numberReady: 1

    # The number of nodes that should be running the
    # daemon pod and have one or more of the daemon pod running and
    # available (ready for at least spec.minReadySeconds)
    numberAvailable: 1

  driverContainer:
    desiredNumberScheduled: 1
    numberReady: 1
    numberAvailable: 1
```

## Reconciliation loop

![Reconciliation loop](reconciliation-module.png)