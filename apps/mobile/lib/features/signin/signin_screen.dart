import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/auth.dart';

class SignInScreen extends ConsumerWidget {
  const SignInScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final auth = ref.watch(authProvider);
    final error = auth is SignedOut ? auth.error : null;
    final busy = auth is AuthLoading;
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            const Spacer(),
            const Icon(Icons.terminal, size: 56),
            const SizedBox(height: 16),
            Text('Private Remote Workspace', textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 12),
            const Text('Open terminals on your own computers from this phone, through your own server.',
                textAlign: TextAlign.center),
            const Spacer(),
            if (error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: Text(error, textAlign: TextAlign.center, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ),
            FilledButton.icon(
              onPressed: busy ? null : () => ref.read(authProvider.notifier).signIn(),
              icon: busy ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.login),
              label: const Text('Sign in with Google'),
            ),
            const SizedBox(height: 12),
            Text('This phone gets its own key, kept in its secure hardware. It can reach no computer until you grant access.',
                textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodySmall),
          ]),
        ),
      ),
    );
  }
}
