/*
Copyright 2020 The Flux CD contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
)

func ReadyCondition(reason, message string) sourcev1.SourceCondition {
	return sourcev1.SourceCondition{
		Type:               sourcev1.ReadyCondition,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}

func NotReadyCondition(reason, message string) sourcev1.SourceCondition {
	return sourcev1.SourceCondition{
		Type:               sourcev1.ReadyCondition,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}

func ReadyGitRepository(repository sourcev1.GitRepository, artifact sourcev1.Artifact, url, reason, message string) sourcev1.GitRepository {
	repository.Status.Conditions = []sourcev1.SourceCondition{ReadyCondition(reason, message)}
	repository.Status.URL = url

	if repository.Status.Artifact != nil {
		if repository.Status.Artifact.Path != artifact.Path {
			repository.Status.Artifact = &artifact
		}
	} else {
		repository.Status.Artifact = &artifact
	}

	return repository
}

func NotReadyGitRepository(repository sourcev1.GitRepository, reason, message string) sourcev1.GitRepository {
	repository.Status.Conditions = []sourcev1.SourceCondition{NotReadyCondition(reason, message)}
	return repository
}

func GitRepositoryReadyMessage(repository sourcev1.GitRepository) string {
	for _, condition := range repository.Status.Conditions {
		if condition.Type == sourcev1.ReadyCondition {
			return condition.Message
		}
	}
	return ""
}

func ReadyHelmRepository(repository sourcev1.HelmRepository, artifact sourcev1.Artifact, url, reason, message string) sourcev1.HelmRepository {
	repository.Status.Conditions = []sourcev1.SourceCondition{ReadyCondition(reason, message)}
	repository.Status.URL = url

	if repository.Status.Artifact != nil {
		if repository.Status.Artifact.Path != artifact.Path {
			repository.Status.Artifact = &artifact
		}
	} else {
		repository.Status.Artifact = &artifact
	}

	return repository
}

func NotReadyHelmRepository(repository sourcev1.HelmRepository, reason, message string) sourcev1.HelmRepository {
	repository.Status.Conditions = []sourcev1.SourceCondition{NotReadyCondition(reason, message)}
	return repository
}

func HelmRepositoryReadyMessage(repository sourcev1.HelmRepository) string {
	for _, condition := range repository.Status.Conditions {
		if condition.Type == sourcev1.ReadyCondition {
			return condition.Message
		}
	}
	return ""
}
